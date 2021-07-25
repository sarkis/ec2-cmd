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
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string
var filterMap map[string]string
var insecure bool
var region string

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
		workers := make(chan struct{}, 10)

		// pipeline of goroutines using unidirectional channels for communication
		// filterInstances -> executeCommand -> printOutput
		go filterInstances(instances)
		go executeCommand(instances, output, workers, args[0])
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

	// Only using PersistentFlags since the CLI has no subcommands
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.ec2-cmd.yaml)")
	rootCmd.PersistentFlags().StringToStringVarP(&filterMap, "filter", "f", nil, "filters in the form of Key=Value")
	rootCmd.PersistentFlags().BoolVarP(&insecure, "insecure", "i", false, "disable host key checks on ssh invocation (which is a security risk!)")
	rootCmd.PersistentFlags().StringVarP(&region, "region", "r", "", "set the AWS region (default: value of AWS_REGION environment variable if set)")
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

	// Bind region to AWS_REGION environment variable
	viper.BindEnv("region", "AWS_REGION")
	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}

func filterInstances(out chan<- ec2.Instance) {
	session := session.Must(session.NewSession(&aws.Config{
		Region: aws.String(region),
	}))

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

func executeCommand(in <-chan ec2.Instance, out chan<- string, workers chan struct{}, cmd string) {
	var wg sync.WaitGroup
	for i := range in {
		wg.Add(1)
		privateIpAddress := *i.PrivateIpAddress

		// Set instance identifier in output as the privateIpAddress by default
		instance := privateIpAddress

		// If there is a Name set on the ec2 instance use that as the identifier instead
		for _, t := range i.Tags {
			if *t.Key == "Name" {
				instance = *t.Value
			}
		}

		// construct the args passed to SSH
		var sshArgs []string
		if insecure {
			sshArgs = append(sshArgs, "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR")
		}

		go func(instance string, privateIpAddress string, o chan<- string) {
			defer wg.Done()

			// use workers channel as a concurrency limiter
			workers <- struct{}{}

			sshArgs = append(sshArgs, privateIpAddress, cmd)

			// Run ssh using exec instead of go lib so OpenSSH configs (~/.ssh/config) are used
			cmd := exec.Command("ssh", sshArgs...)
			var stdoutBuf bytes.Buffer
			cmd.Stdout = &stdoutBuf
			// not checking err here so a single ec2 instance failure doesn't cancel on the remaining
			err := cmd.Run()
			if err != nil {
				fmt.Println(err)
			}
			o <- fmt.Sprintf("[%s]:\n%s", instance, stdoutBuf.String())
			<-workers // free up a worker
		}(instance, privateIpAddress, out)
	}

	go func() {
		wg.Wait()
		close(out)
	}()
}

func printOutput(in <-chan string) {
	for o := range in {
		fmt.Println(o)
	}
}
