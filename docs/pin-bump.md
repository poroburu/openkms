# Pin bump workflow

After changing this repo, bump the pin in the parent [`openKMSio/okms`](https://github.com/openKMSio/okms) so teammates get the new SHA on recurse clone.

```bash
# 1. In this child
git add -A && git commit -m "..." && git push

# 2. In parent okms/
cd ..   # or your okms checkout
git add openkms
git commit -m "chore: bump openkms"
git push
```

Verify:

```bash
git -C .. submodule status openkms
```
