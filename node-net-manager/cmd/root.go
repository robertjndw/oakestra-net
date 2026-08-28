package cmd

import (
	"NetManager/logger"
	"NetManager/model"
	"NetManager/network"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"NetManager/server"

	"github.com/spf13/cobra"
	"github.com/tkanos/gonfig"
)

var (
	rootCmd = &cobra.Command{
		Use:   "NetManager",
		Short: "Start a NetManager",
		Long:  `Start a New Oakestra Worker Node`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return startNetManager()
		},
	}
	cfgFile   string
	localPort int
	noEbpf    bool
)

const MONITORING_CYCLE = time.Second * 2

func Execute() error {
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.Flags().BoolVar(&noEbpf, "no-ebpf", false, "Disable the eBPF fast path and force pure ProxyTUN, overriding EbpfEnabled in netcfg.json")
	return rootCmd.Execute()
}

func init() {
	cfgFile = "/etc/netmanager/netcfg.json"
}

func startNetManager() error {

	err := gonfig.GetConf(cfgFile, &model.NetConfig)
	if err != nil {
		log.Fatalf("Unable to load config file: %s", err)
	}

	if noEbpf {
		model.NetConfig.EbpfEnabled = false
	}

	if model.NetConfig.Debug {
		logger.SetDebugMode()
	}

	log.Print(model.NetConfig)

	network.IptableFlushAll()

	// Detach the eBPF fast path (if it ever attached) before the process
	// exits, so a restart never finds stale TC filters left on interfaces
	// that outlive this process.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		logger.InfoLogger().Println("Shutting down")
		server.Shutdown()
		os.Exit(0)
	}()

	log.Println("NetManager started, but waiting for NodeEngine registration 🟠")
	server.HandleRequests(localPort)

	return nil

}
