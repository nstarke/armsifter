# Armsifter

A few years ago I was really inspired by [sandsifter](https://github.com/xoreaxeaxeax/sandsifter) and wanted to try my hand at building something similar that targeted 32-bit ARM processors.  There were a few other, better written CPU Instruction Fuzzers for ARM, so I didn't pursue publishing the project in full at the time.

The way I ran this was across a cluster of 16 Raspberry Pi Zero W hosts running raspbian.  They would boot up, pull the repository, and begin executing.  Even with 16 different instances, it would have taken months to execute the entire 32-bit address range as instructions on this bare-metal setup.  However, the benefit of doing it this way is the potential to discover chipset-specific odd instructions that might be useful to a hacker.

I am releasing this work in case anyone else wants to experiment with this approach.  If you find something cool, consider linking back to this project!

## Dependencies

Requires Capstone to compile correctly.  On debian-based hosts, this can be installed with the following command:

```
sudo apt install libcapstone-dev
```