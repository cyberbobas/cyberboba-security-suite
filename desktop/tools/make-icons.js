#!/usr/bin/env node
// Generates the tray icons and the application icon as PNG files using only
// Node's zlib (no image libraries). Run: node tools/make-icons.js
//
//   assets/tray-on.png      22x22  blue cyberboba (proxify ON)
//   assets/tray-on-32.png   32x32
//   assets/tray-off.png     22x22  grey cyberboba (proxify OFF)
//   assets/tray-off-32.png  32x32
//   build/icon.png          256x256 app icon (rounded dark tile + blue cyberboba)
//   assets/icon.png         same, shipped inside the app (window icon, dev autostart)

'use strict';
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

// ---------------------------------------------------------------- PNG encoder
const CRC_TABLE = new Uint32Array(256);
for (let n = 0; n < 256; n++) {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  CRC_TABLE[n] = c >>> 0;
}
function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const td = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(td), 0);
  return Buffer.concat([len, td, crc]);
}
// rgba: Uint8Array of w*h*4
function encodePNG(w, h, rgba) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0);
  ihdr.writeUInt32BE(h, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // colour type RGBA
  ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;
  const stride = w * 4;
  const raw = Buffer.alloc((stride + 1) * h);
  for (let y = 0; y < h; y++) {
    raw[y * (stride + 1)] = 0; // filter: none
    Buffer.from(rgba.buffer, rgba.byteOffset + y * stride, stride).copy(raw, y * (stride + 1) + 1);
  }
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', zlib.deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

// ---------------------------------------------------------------- rasteriser
// Shapes are described in normalised coordinates (0..1, y down) and rendered
// with supersampling for anti-aliasing.
function rect(x0, y0, x1, y1) { return (x, y) => x >= x0 && x < x1 && y >= y0 && y < y1; }
function tri(ax, ay, bx, by, cx, cy) {
  return (x, y) => {
    const d1 = (x - bx) * (ay - by) - (ax - bx) * (y - by);
    const d2 = (x - cx) * (by - cy) - (bx - cx) * (y - cy);
    const d3 = (x - ax) * (cy - ay) - (cx - ax) * (y - ay);
    const neg = d1 < 0 || d2 < 0 || d3 < 0;
    const pos = d1 > 0 || d2 > 0 || d3 > 0;
    return !(neg && pos);
  };
}
function roundedRect(x0, y0, x1, y1, r) {
  return (x, y) => {
    if (x < x0 || x >= x1 || y < y0 || y >= y1) return false;
    const cx = Math.min(Math.max(x, x0 + r), x1 - r);
    const cy = Math.min(Math.max(y, y0 + r), y1 - r);
    return (x - cx) ** 2 + (y - cy) ** 2 <= r * r;
  };
}

// CyberBoba glyph: three prongs with pointed tips joined by a crossbar, a shaft
// and a small pommel. `t` is the stroke thickness in normalised units.
function cyberbobaShapes(t) {
  const cx = 0.5;
  const lx = 0.17, rx = 0.83;        // outer prong centres
  const tipTop = 0.06, tipLen = 0.14;
  const prongBottom = 0.56;          // crossbar centre line
  const shapes = [];
  for (const px of [lx, cx, rx]) {
    const top = px === cx ? tipTop - 0.04 : tipTop;
    shapes.push(rect(px - t / 2, top + tipLen, px + t / 2, prongBottom + t / 2));
    shapes.push(tri(px, top, px - t * 0.95, top + tipLen + 0.02, px + t * 0.95, top + tipLen + 0.02));
  }
  shapes.push(rect(lx - t / 2, prongBottom - t / 2, rx + t / 2, prongBottom + t / 2)); // crossbar
  shapes.push(rect(cx - t / 2, prongBottom, cx + t / 2, 0.95));                        // shaft
  shapes.push(rect(cx - t * 1.4, 0.92, cx + t * 1.4, 0.92 + t * 0.8));                 // pommel
  return shapes;
}

function render(size, layers, ss = 4) {
  const rgba = new Uint8Array(size * size * 4);
  for (let py = 0; py < size; py++) {
    for (let px = 0; px < size; px++) {
      let r = 0, g = 0, b = 0, a = 0; // premultiplied accumulators
      for (let sy = 0; sy < ss; sy++) {
        for (let sx = 0; sx < ss; sx++) {
          const x = (px + (sx + 0.5) / ss) / size;
          const y = (py + (sy + 0.5) / ss) / size;
          // composite layers top-down: last layer wins where it covers
          let cr = 0, cg = 0, cb = 0, ca = 0;
          for (const layer of layers) {
            if (layer.shapes.some((s) => s(x, y))) {
              const la = layer.color[3] / 255;
              cr = layer.color[0] * la + cr * (1 - la);
              cg = layer.color[1] * la + cg * (1 - la);
              cb = layer.color[2] * la + cb * (1 - la);
              ca = la + ca * (1 - la);
            }
          }
          r += cr; g += cg; b += cb; a += ca;
        }
      }
      const n = ss * ss;
      const i = (py * size + px) * 4;
      const alpha = a / n;
      if (alpha > 0) {
        rgba[i] = Math.round(r / n / alpha);
        rgba[i + 1] = Math.round(g / n / alpha);
        rgba[i + 2] = Math.round(b / n / alpha);
        rgba[i + 3] = Math.round(alpha * 255);
      }
    }
  }
  return rgba;
}

// ---------------------------------------------------------------- outputs
const root = path.resolve(__dirname, '..');
const BLUE = [76, 141, 255, 255];   // --accent in the daemon UI
const GREY = [150, 156, 166, 255];
const TILE = [15, 17, 21, 255];     // #0f1115

function write(rel, w, rgba) {
  const file = path.join(root, rel);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, encodePNG(w, w, rgba));
  console.log(`wrote ${rel} (${w}x${w}, ${fs.statSync(file).size} bytes)`);
}

for (const [name, color] of [['on', BLUE], ['off', GREY]]) {
  for (const size of [22, 32]) {
    // Slightly thicker stroke at 22px so it stays readable on a panel.
    const t = size <= 22 ? 0.16 : 0.14;
    const rgba = render(size, [{ shapes: cyberbobaShapes(t), color }], 6);
    write(`assets/tray-${name}${size === 22 ? '' : '-' + size}.png`, size, rgba);
  }
}

{
  const size = 256;
  const glyph = cyberbobaShapes(0.11).map((s) => (x, y) => s((x - 0.5) * 1.35 + 0.5, (y - 0.5) * 1.35 + 0.5));
  const rgba = render(size, [
    { shapes: [roundedRect(0.02, 0.02, 0.98, 0.98, 0.18)], color: TILE },
    { shapes: [roundedRect(0.02, 0.02, 0.98, 0.98, 0.18)], color: [76, 141, 255, 24] },
    { shapes: glyph, color: BLUE },
  ], 4);
  write('build/icon.png', size, rgba);
  write('assets/icon.png', size, rgba);
}
