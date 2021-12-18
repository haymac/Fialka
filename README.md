# Fialka M-125
# WORK IN PROGRESS
![alt text](https://raw.githubusercontent.com/phrutis/LostCoins/main/Others/4.jpg "Fialka M-125")
- This is a modified version [LostCoins](https://github.com/phrutis/LostCoins/). 
- Huge thanks [kanhavishva](https://github.com/kanhavishva) and to all developers whose codes were used in Fialka M-125.
## Quick start
- Сonvert addresses 1... into binary hashes RIPEMD160 use [b58dec.exe](https://github.com/phrutis/LostCoins/blob/main/Others/b58dec.exe) Сommand: ```b58dec.exe addresses.txt base160.bin```
- It is important to sort the base160.bin file otherwise the Bloom search filter will not work as expected.
- To SORT base160.bin use the program [RMD160-Sort.exe](https://github.com/phrutis/LostCoins/blob/main/Others/RMD160-Sort.exe) Сommand: ```RMD160-Sort.exe base160.bin hex160-Sort.bin``` 
# Parametrs:
Run: ```Fialka.exe -h```

```
Usage: Fialka M-125 [options...]
Options:
    -v, --version          Print version. For help visit https://github.com/phrutis/LostCoins
    -c, --check            Check the working of the code LostCoins
    -u, --uncomp           Search only Uncompressed addresses
    -b, --both             Search both (Uncompressed and Compressed addresses)
    -g, --gpu              Enable GPU calculation
    -i, --gpui             GPU ids: 0,1...: List of GPU(s) to use, default is 0
    -x, --gpux             GPU gridsize: g0x,g0y,g1x,g1y, ...: Specify GPU(s) kernel gridsize, default is 8*(MP number),128
    -t, --thread           ThreadNumber: Specify number of CPUs thread, default is number of core
    -o, --out              Outputfile: Output results to the specified file, default: Found.txt
    -m, --max              -m  1-10000 For GPU: Reloads random started hashes every billions in counter. Default: 100 billion
    -s, --seed             PassPhrase   (Start bit range)
    -z, --zez              PassPhrase 2 (End bit range)
    -e, --nosse            Disable SSE hash function. Use for older CPU processor if it fails 
    -r, --rkey             Number of random modes
    -n, --nbit             Number of letters and number bit range 1-256
    -f, --file             RIPEMD160 binary hash file path
    -d, --diz              Display modes -d 0 [info+count], -d 1 SLOW speed [info+hex+count], Default -d 2 [count] HIGH speed
    -k, --color            Text color: -k 1-255 Recommended 3, 10, 11, 14, 15 (default: -k 15)
    -h, --help             Shows this page
 ```
## Mode 0 
### Search Passphrases
- [*Use old databases or a generator to create Passphrases, Minikeys, WIF, HEX*](https://github.com/phrutis/LostCoins/blob/main/Others/Modes.md) 
- The list of found passphrases is [here](https://privatekeys.pw/brainwallet/bitcoin/1) and [here](https://allprivatekeys.com/hacked-brainwallets-with-balance)
### Find Passphrases, minikeys and Privat keys from a text file
- [*How to use + examples*](https://github.com/phrutis/Fialka/issues/1)
#### To search for Passphrases, use **-u** or **-b** (-t 11 max)
 - Run: ```Fialka.exe -b -t 11 -r 0 -s Passphrases.txt -z Passphrases -f test.bin``` 
#### To search for [Minikey](https://en.bitcoin.it/wiki/Mini_private_key_format) (S.. 22, 30 letters)
 - Run: ```Fialka.exe -t 11 -r 0 -s Minikeys.txt -z Passphrases -f test.bin```
#### To search for Private keys WIF
 - Run: ```Fialka.exe -t 11 -r 0 -s Private-keys-wif.txt -z WIF -f test.bin```
#### To search for Private keys HEX
 - Run: ```Fialka.exe -t 11 -r 0 -s Private-keys-hex.txt -z HEX -f test.bin```

## Mode 1
### Parallel Passphrases search with continuation
- [*How to use + examples*](https://github.com/phrutis/Fialka/issues/2)


## Mode 2
### Parallel Minikeys search with continuation
- [*How to use + examples*](https://github.com/phrutis/Fialka/issues/3)

## Mode 3
### Parallel WIF search with continuation
- [*How to use + examples*](https://github.com/phrutis/Fialka/issues/4)

## Mode 4
### Parallel Passphrases search with continuation
- [*How to use + examples*](https://github.com/phrutis/Fialka/issues/5)

## Mode 5
### Parallel Passphrases search with continuation
- [*How to use + examples*](https://github.com/phrutis/Fialka/issues/6)

## Mode 6
### Parallel Passphrases search with continuation
- [*How to use + examples*](https://github.com/phrutis/Fialka/issues/7)

## Mode 7
### GPU Parallel WIF search with continuation
- [*How to use + examples*](https://github.com/phrutis/Fialka/issues/8)


## VanitySearch special edition for Fialka M-125
[*Example search WIF*](https://github.com/phrutis/Fialka/issues/1)



## Building
- Microsoft Visual Studio Community 2019
- CUDA version [**10.22**](https://developer.nvidia.com/cuda-10.2-download-archive?target_os=Windows&target_arch=x86_64&target_version=10&target_type=exenetwork)
## Donation
- BTC: bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9
## License
LostCoins is licensed under GPL v3.0
## Disclaimer
ALL THE CODES, PROGRAM AND INFORMATION ARE FOR EDUCATIONAL PURPOSES ONLY. USE IT AT YOUR OWN RISK. THE DEVELOPER WILL NOT BE RESPONSIBLE FOR ANY LOSS, DAMAGE OR CLAIM ARISING FROM USING THIS PROGRAM.
