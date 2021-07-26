# ec2-cmd
A CLI that takes in optional filters and a command to run on matching EC2 instances
via SSH.

## Auth
Authentication and configuration to the correct AWS account and SSH configs are
required outside of the `ec2-cmd` CLI. The following assumptions are made:

* AWS authentication is setup in `~/.aws/credentials` and proper environment variables are set.
See tools like [aws-vault](https://github.com/99designs/aws-vault) if you need to configure this.
* SSH configs are set in `~/.ssh/config` for connecting to EC2 instances via their private ip addresses

# Usage
```
Usage:
  ec2-cmd [flags] COMMAND

Flags:
      --config string           config file (default is $HOME/.ec2-cmd.yaml)
  -f, --filter stringToString   filters in the form of Key=Value (default [])
  -h, --help                    help for ec2-cmd
  -i, --insecure                disable host key checks on ssh invocation (which is a security risk!)
  -p, --parallel int            number of parallel executions (default: 10) (default 10)
  -r, --region string           set the AWS region (default: value of AWS_REGION environment variable if set)
```
