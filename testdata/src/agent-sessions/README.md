# Agent Sessions Test Case

This directory contains the SSM agent as a submodule and a patch file that modifies the session protocol implementation on which we want to apply ARGOT.
Apply the patch file by switching to the submodule's root directory and apply the patch file there, i.e.,:
```
cd amazon-ssm-agent
git apply ../sessions.patch
```
