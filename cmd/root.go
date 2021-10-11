/*
Copyright © 2020 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/masahide/mysql-audit-proxy/pkg/mysql"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	conf    = mysql.Config{
		Net:             "tcp",
		Addr:            "localhost:3330",
		LogFileName:     "mysql-audit.%Y%m%d%H.log",
		RotateTime:      1 * time.Hour,
		QueueSize:       200,
		BufSize:         "32mb",
		EncodeType:      mysql.EncodeTypeGOB,
		BufferFlushTime: 1 * time.Second,
	}
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "mysql-audit-proxy",
	Short: "proxy server to get audit logs for mysql",
	Long:  `proxy server to get audit logs for mysql`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	Run: func(cmd *cobra.Command, args []string) {
		ctx, cancel := context.WithCancel(context.Background())
		sc := make(chan os.Signal, 1)
		signal.Notify(sc, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
		go func() {
			sig := <-sc
			log.Printf("main Got signal: %s", sig)
			cancel()
		}()
		svr, err := mysql.NewServer(ctx, &conf)
		if err != nil {
			log.Fatal(err)
		}
		if err = svr.Run(ctx); err != nil {
			log.Println(err)
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	//rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.mysql-audit-proxy.yaml)")
	rootCmd.PersistentFlags().StringVar(&conf.Net, "net", conf.Net, "Listen net ['tcp' or 'unix'] ")
	rootCmd.PersistentFlags().StringVar(&conf.Addr, "listen", conf.Addr, "Listen address [ip or hostname or socketFileName] ")
	rootCmd.PersistentFlags().StringVar(&conf.LogFileName, "log", conf.LogFileName, "logfile path")
	rootCmd.PersistentFlags().BoolVar(&conf.LogGzip, "logGzip", conf.LogGzip, "Gzip compress log files")
	rootCmd.PersistentFlags().DurationVar(&conf.RotateTime, "rotate", conf.RotateTime, "logfile rotatetime")
	rootCmd.PersistentFlags().IntVar(&conf.QueueSize, "q", conf.QueueSize, "max log buffer queues")
	rootCmd.PersistentFlags().StringVar(&conf.BufSize, "buf", conf.BufSize, "buffer size")
	rootCmd.PersistentFlags().DurationVar(&conf.BufferFlushTime, "flush", conf.BufferFlushTime, "time to flush buffer")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	// rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Search config in home directory with name ".mysql-audit-proxy" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".mysql-audit-proxy")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}
