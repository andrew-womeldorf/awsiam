# AWSIAM

I want a tool that I can view all of the policy documents applied to an AWS IAM
Role in a single command.

I'd rather use an existing tool, but I haven't found one. The scope of this
could be greatly extended; contributions welcome.

## Usage

```bash
awsiam <rolename> [<filter>]
```

- Where `rolename` is the name (not ARN) of a role in the AWS account.
- Where `filter` is an optional string prefix of an action.

## Example

Show all statements across all applied policies for `my-role` where the action
is prefixed with `s3`:

```bash
awsiam my-role s3
```
