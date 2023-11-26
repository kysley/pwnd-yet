# pwnd-yet
A CLI tool extending the [haveibeenpwned.com](https://haveibeenpwned.com/api/v3) api.


## Usage
```bash
> pwn --o <password>
// Output:
> Password pwned 😵

> pwn pw add <website> <password>
> pwn
// Output:
// Checking <website>
// Password pwned 😵
```
## Specs
- pwn hashes your password using sha1 then takes the first 5 characters and sends them to haveibeenpwned.
- If adding a password:
  - The password's sha1 undergoes a simple encryption to avoid storing plain values in a .txt. **This is not intended to be a vault.**
  - Delete `pwn.txt` to clear saved passwords
