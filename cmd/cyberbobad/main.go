// cyberbobad is the cyberboba daemon: transparent proxifier, VPN manager and
// Caido integration. It must run as root for interception and VPNs.
package main

import (
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/signal"
	"syscall"

	"cyberboba/internal/api"
	"cyberboba/internal/app"
	"cyberboba/internal/config"
	"cyberboba/web"
)

func main() {
	cfgPath := flag.String("config", config.DefaultPath, "configuration file")
	runDir := flag.String("run-dir", "/run/cyberboba", "runtime directory")
	listen := flag.String("listen", "", "override api.listen (web UI address)")
	noNF := flag.Bool("no-netfilter", false, "do not install iptables rules (debug)")
	initCfg := flag.Bool("init", false, "write a default configuration file and exit")
	version := flag.Bool("version", false, "print version")
	flag.Parse()
	if *version {
		fmt.Println("cyberbobad", app.Version)
		return
	}
	if *initCfg {
		if _, err := os.Stat(*cfgPath); err == nil {
			log.Fatalf("%s already exists", *cfgPath)
		}
		if err := config.Default().Save(*cfgPath); err != nil {
			log.Fatal(err)
		}
		fmt.Println("wrote", *cfgPath)
		return
	}
	log.SetFlags(log.Ltime)
	cfg, err := config.Load(*cfgPath, true)
	if err != nil {
		log.Fatal(err)
	}
	if *listen != "" {
		cfg.API.Listen = *listen
	}
	if *noNF {
		cfg.Proxifier.Enabled = false
	}
	store := config.NewStore(*cfgPath, cfg)
	d := app.New(store, *runDir)
	if err := d.Start(); err != nil {
		log.Fatal(err)
	}
	sub, _ := fs.Sub(web.FS, ".")
	srv := api.New(d, sub)
	if err := srv.ListenAndServe(cfg.API.UnixSocket, cfg.API.Listen, cfg.API.Token); err != nil {
		d.Stop()
		log.Fatal(err)
	}
	if cfg.API.Listen != "" {
		log.Printf("web ui: http://%s/", cfg.API.Listen)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	srv.Shutdown()
	d.Stop()
}
