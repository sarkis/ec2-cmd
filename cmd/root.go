/*
Copyright © 2021 Sarkis Varozian <svarozian@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package cmd

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string
var filterMap map[string]string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "ec2-cmd [flags] COMMAND",
	Short: "Run commands on EC2 instances in parallel via ssh",
	Long: `ec2-cmd is a CLI which takes in tags and values to filter on and
		runs a command through SSH on the matching EC2 instances. Example usage:
		
		ec2-cmd --filter "tag:Name=dev-ec2-*" "uname -a"
		`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// TODO: make the buffer size configurable, this will
		// determine maximum ssh sessions to run in parallel
		// set at 10 for now
		instances := make(chan ec2.Instance, 10)
		output := make(chan string, 10)

		// pipeline of goroutines using unidirectional channels for communication
		// filterInstances -> executeCommand -> printOutput
		go filterInstances(instances)
		go executeCommand(instances, output, args[0])
		printOutput(output)
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.ec2-cmd.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().StringToStringVarP(&filterMap, "filter", "f", nil, "filters in the form of Key=Value")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".ec2-cmd" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".ec2-cmd")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}

func filterInstances(out chan<- ec2.Instance) {
	session := session.Must(session.NewSession())

	ec2svc := ec2.New(session)

	// Add filters for describe instances call from flag
	var filters []*ec2.Filter
	for k, v := range filterMap {
		filters = append(filters, &ec2.Filter{
			Name:   aws.String(k),
			Values: []*string{aws.String(v)},
		})
	}

	params := &ec2.DescribeInstancesInput{
		Filters: filters,
	}

	resp, err := ec2svc.DescribeInstances(params)
	if err != nil {
		fmt.Println("there was an error listing instances in", err.Error())
		log.Fatal(err.Error())
	}
	for idx := range resp.Reservations {
		for _, inst := range resp.Reservations[idx].Instances {
			out <- *inst
		}
	}
	close(out)
}

func executeCommand(in <-chan ec2.Instance, out chan<- string, cmd string) {
	for i := range in {
		privateIpAddress := *i.PrivateIpAddress

		// Set instance identifier in output as the privateIpAddress by default
		instance := privateIpAddress

		// If there is a Name set on the ec2 instance use that as the identifier instead
		for _, t := range i.Tags {
			if *t.Key == "Name" {
				instance = *t.Value
			}
		}

		// Run ssh using exec instead of go lib so OpenSSH configs (~/.ssh/config) are used
		cmd := exec.Command("ssh", privateIpAddress, cmd)
		var stdoutBuf bytes.Buffer
		cmd.Stdout = &stdoutBuf
		// not checking err here so a single ec2 instance failure doesn't cancel on the remaining
		cmd.Run()
		out <- fmt.Sprintf("[%s]:\n%s", instance, stdoutBuf.String())
	}
	close(out)
}

func printOutput(in <-chan string) {
	for o := range in {
		fmt.Println(o)
	}
}
