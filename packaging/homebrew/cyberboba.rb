# Homebrew formula (Linux / Linuxbrew). CyberBoba is a Linux daemon that needs
# root + iptables for transparent interception and VPNs; Homebrew installs the
# binaries only (no systemd unit). For the full system install use the AUR
# package, the .tar.gz release, or `make install`. On macOS it will not run.
#
#   brew install --build-from-source ./packaging/homebrew/cyberboba.rb
class Cyberboba < Formula
  desc "Agent-first Linux network-security suite (proxifier, VPN, MITM proxy, firewall, MCP)"
  homepage "https://github.com/cyberbobas/cyberboba-security-suite"
  url "https://github.com/cyberbobas/cyberboba-security-suite/archive/refs/tags/v0.2.0.tar.gz"
  license "Apache-2.0"
  head "https://github.com/cyberbobas/cyberboba-security-suite.git", branch: "main"

  depends_on "go" => :build
  depends_on :linux

  def install
    ENV["CGO_ENABLED"] = "0"
    system "make", "build"
    bin.install "bin/cyberbobad"
    bin.install "bin/cyberboba"
    pkgetc.install "packaging/config.example.yaml" => "config.yaml"
  end

  def caveats
    <<~EOS
      CyberBoba needs root + iptables to run its transparent proxy, VPNs and
      firewall. Homebrew installed the binaries only. For a system service use
      the AUR package or `sudo make install` from the source tree.
    EOS
  end

  test do
    assert_match "cyberbobad", shell_output("#{bin}/cyberbobad --version")
  end
end
