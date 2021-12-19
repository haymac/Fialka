# Fialka M-125
# WORK IN PROGRESS
![alt text](https://raw.githubusercontent.com/phrutis/LostCoins/main/Others/4.jpg "Fialka M-125")
- This is a modified version [LostCoins](https://github.com/phrutis/LostCoins/) 
- Huge thanks [kanhavishva](https://github.com/kanhavishva) and to all developers whose codes were used in Fialka M-125.
## Quick start
- Сonvert addresses 1... into binary hashes RIPEMD160 use [b58dec.exe](https://github.com/phrutis/Fialka/blob/main/Others/b58dec.exe) Run: ```b58dec.exe addresses.txt base160.bin```
- It is important to sort the base160.bin file otherwise the Bloom search filter will not work as expected.
- To SORT base160.bin use the program [RMD160-Sort.exe](https://github.com/phrutis/Fialka/blob/main/Others/RMD160-Sort.exe) Run: ```RMD160-Sort.exe base160.bin hex160-Sort.bin``` 
# Parametrs:
Run: ```Fialka.exe -h```

```
Usage: Fialka M-125 [options...]
Options:
    -v, --version          Print version. For help visit https://github.com/phrutis/Fialka
    -u, --uncomp           Search only uncompressed addresses 
    -b, --both             Search both (uncompressed and compressed addresses)
    -g, --gpu              Enable GPU calculation
    -i, --gpui             GPU ids: 0,1...: List of GPU(s) to use, default is 0
    -x, --gpux             GPU gridsize: g0x,g0y,g1x,g1y, ...: Specify GPU(s) kernel gridsize, default is 8*(MP number),128
    -t, --thread           CPU number of cores and threads
    -o, --out              Output results Found to the specified text file. Default: Found.txt
    -m, --max              -m 1-256 Range bit limiter
    -s, --seed             Text file name or other
    -z, --zez              Additional meaning or other
    -e, --nosse            Disable SSE hash function
    -r, --rkey             Number of Modes
    -n, --nbit             Number of letters or other
    -f, --file             RIPEMD160 binary SORT hash file path with addresses 1... 
    -h, --help             Shows this page
 ```
## Mode 0 
- [Use old databases or a generator to create list Passphrases, Minikeys, WIF, HEX](https://github.com/phrutis/LostCoins/blob/main/Others/Modes.md) 
- The list of Found passphrases is [here](https://privatekeys.pw/brainwallet/bitcoin/1) and [here](https://allprivatekeys.com/hacked-brainwallets-with-balance)
- There is a ready-made file [test.bin](https://github.com/phrutis/Fialka/blob/main/Others/test.bin) inside 8 words of 3 letters 
- Uncomressed: cat, gaz, for, car 
- Compressed: abc, cop, run, zip
- [Make your own](https://brainwalletx.github.io/) passphrase or minikeys for test
- There is a ready-made file [test.bin](https://github.com/phrutis/Fialka/blob/main/Others/test.bin) inside 8 WIF: 
- 4 WIF Uncomressed: 
5JiznUZskJpwodP3SR85vx5JKeopA3QpTK63BuziW8RmGGyJg81 
5KMdQbcUFS3PBbC6VgitFrFuaca3gBY4BJt4jpQ2YTNdPZ1CbuE 
5HwfeuhdFscL9YTQCLT2952dieZEtKbzJ328b4CR1v6YUVLu2D7 
5J9J63iW7s5p54T569qstediqNgBTLXpUmxUtQwsXTaHz3JCsKt
- 4 WIF Compressed: 
L3UBXym7JYcMX91ssLgZzS2MvxTxjU3VRf9S4jJWXVFdDi4NsLcm 
L3BEabkqcsppnTdzAWiizPEuf3Rvr8QEac21uRVsYb9hjesWBxuF 
L31UCqx296TVRtgpCJspQJYHkwUeA4o3a2pvYKwRrCCAmi2NirDG 
KyiR31LZTQ2hk1DRxEticnsQCA8tjFZcgJiKNaRArZME5fpfAjWj
- [Make your own](https://secretscan.org/PrivateKeyWif) WIF or HEX for test
- For search Uncompressed WIF 5.. (51 length) use the **-b** parameter!

### Find Passphrases, minikeys and Privat keys from a text file
- Work only in CPU
- -t ? how many cores (threads) to use? 1-11 max
- If CPU 64 cores, you can run 6 copies of the program -t 10 with different dictionaries.txt 
- For text files less than 100,000 use -t 1 
- Maximun lines in text file 2,147,483,647 on a new line 
- if the file is larger, cut into EmEditor chunks by 2,000,000,000 lines 
- The last two lines in the file are **LOST**! 

#### To search for Passphrases, use -u or -b
- For Passphrases use only letters and symbols: A-Za-z0-9А-Яа-яёЁьЪЬъ `~!@#$&*()-_=+{}|;:'<>,./? others will be Skipped!
- Run: ```Fialka.exe -b -t 1 -r 0 -s Dictionaries.txt -z Passphrases -f test.bin``` 

![alt text](https://raw.githubusercontent.com/phrutis/Fialka/main/Others/img/r0.jpg "Fialka M-125")

#### To search for [Minikeys](https://en.bitcoin.it/wiki/Mini_private_key_format)
 - For Minikeys S... (length 22) or S... (length 30)
 - Run: ```Fialka.exe -t 1 -r 0 -s Minikeys-list.txt -z Passphrases -f test.bin```

#### To search for Private keys WIF
 - For WIF **ONLY !** letters and symbols Base58 (ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz123456789)
 - For WIF The first letter must be L... (length 52) and K... (length 52) or 5... (length 51) if 5.. WIF is listed use **-b**
 - Run: ```Fialka.exe -t 1 -r 0 -s Private-keys-wif.txt -z WIF -f test.bin```

![alt text](https://raw.githubusercontent.com/phrutis/Fialka/main/Others/img/0wif.jpg "Fialka M-125")

#### To search for Private keys HEX
 - For HEX use only 0,1,3,4,5,6,7,8,9,a,b,c,d,e,f length 1-64 max)
 - Run: ```Fialka.exe -t 1 -r 0 -s Private-keys-hex.txt -z HEX -f test.bin```
```
C:\Users\User>Fialka.exe -t 11 -r 0 -s private-keys.txt -z HEX -f test.bin

 Fialka M-125 (18.12.2021)

 SEARCH MODE  : COMPRESSED
 DEVICE       : CPU
 CPU THREAD   : 11
 GPU IDS      : 0
 GPU GRIDSIZE : -1x128
 HASH160 FILE : test.bin
 OUTPUT FILE  : Found.txt

 Loading      : 100 %
 Loaded       : 75,471 address

Bloom at 000001E224E704B0
  Version     : 2.1
  Entries     : 150942
  Error       : 0,0000010000
  Bits        : 4340363
  Bits/Elem   : 28,755175
  Bytes       : 542546 (0 MB)
  Hash funcs  : 20

  Start Time  : Sat Dec 18 20:30:04 2021

  Random mode : 0
  Rotor       : Loading Private keys (HEX) from file: private-keys.txt ...ok
  Loaded      : 31510509 HEX private keys
  Rotor       : For files up to 100,000 use -t 1 For large file max to 2,147,483,647 lines use -t 1-11 max
  Site        : https://github.com/phrutis/Fialka
  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9

  [00:01:31] [ba7816bf8f01c0ea414140de5dae2223b00061a396177a9cb410ff61f0961fea] [BA7816BF8F01C0EA414140DE5DAE2223B00061A396177A9CB410FF61F0961FEA] [CPU: 264,22 Kk/s] [F: 0] [T: 17,946,027] [Skip: 0]
  =================================================================================
  * PubAddress: 15KqNGHFEViRS4WTYYJ4TRoDtSXH5ESzW9                                *
  * Priv(WIF) : p2pkh:L3BEabkqcsppnTdzAWiizPEuf3Rvr8QEac21uRVsYb9hjesWBxuF        *
  * Priv(HEX) : B1C02B717C94BD4243E83B5E98BA37FB273BC035E4AD8FC438EA4D07A1043F56  *
  =================================================================================
  [00:01:38] [ba7816bf8f01c0ea414140de5dae2223b00061a396177a9cb410ff61f0a128fe] [BA7816BF8F01C0EA414140DE5DAE2223B00061A396177A9CB410FF61F0A128FD] [CPU: 261,62 Kk/s] [F: 1] [T: 19,934,800] [Skip: 0]
  =================================================================================
  * PubAddress: 14Nmb7rFFLdZhKaud5h7nDSLFQfma7JCz2                                *
  * Priv(WIF) : p2pkh:L31UCqx296TVRtgpCJspQJYHkwUeA4o3a2pvYKwRrCCAmi2NirDG        *
  * Priv(HEX) : ACBA25512100F80B56FC3CCD14C65BE55D94800CDA77585C5F41A887E398F9BE  *
  =================================================================================
  [00:01:42] [ba7816bf8f01c0ea414140de5dae2223b00061a396177a9cb410ff61f0a652be] [BA7816BF8F01C0EA414140DE5DAE2223B00061A396177A9CB410FF61F0A652BE] [CPU: 270,48 Kk/s] [F: 2] [T: 21,094,591] [Skip: 0]
  =================================================================================
  * PubAddress: 1PoQRMsXyQFSqCCRek7tt7umfRkJG9TY8x                                *
  * Priv(WIF) : p2pkh:L3UBXym7JYcMX91ssLgZzS2MvxTxjU3VRf9S4jJWXVFdDi4NsLcm        *
  * Priv(HEX) : BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD  *
  =================================================================================
  [00:02:55] [ba7816bf8f01c0ea414140de5dae2223b00061a396177a9cb410ff61f10dfb8a] [BA7816BF8F01C0EA414140DE5DAE2223B00061A396177A9CB410FF61F10DFB8A] [CPU: 277,55 Kk/s] [F: 3] [T: 41,123,450] [Skip: 0]
  Search is Finish! Found: 3

```

## Mode 1
### Random search WIF from puzzle 64 bit
- VanitySearch Search the prefix 16jY7qLJ from a [puzzles 64 bits](https://privatekeys.pw/puzzles/bitcoin-puzzle-tx) 
- Example WIF out:
KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYvQqYKVuZryGJLxfH1P
KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYwJvoHMhmXgVkKmTcAx
KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYwYTCAfXHKuFsZ2stFG
KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYwdn9fqLaBQKZTm2aUS
KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYwfF8kXepG8TvxzjXag
KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYwxvkRPWm5vSDofLME1
KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYwyWFyQr5iVJkTvXccg
KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYzMHHGVeYFPidEza7Td
KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qZ1pdCSxTJsQuadcciW9
KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qZ2u4BA8jvgN3gncqUhT
KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qZ3hA1yqkkqoyqype3pQ
**KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qZ4CZMY**vJden3dEAzBrN
KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qZ4CvxzWeetic2u7gUbg
KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qZ4ZfAVpwMaXB9RCuyN6
KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qZ5gJ1Z6ViyQfs1XPAbW
KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qZ6QmTJSSvicVo9Le8ZK
- We know that the private key corresponds to 64 bits. Therefore, set the -m 64 range limiter.
- If the output private key is more or less than 64 bits, skip... 
- For 256 bit range use -m 256 or other ranges skip...
- -n ? number of random letters. If prefix 38 letters 52-38 = -n 14 (without сhecksum)
- Run: ```Fialka.exe -t 6 -r 1 -f puzles.bin -s KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qZ4CZMY -n 12 -m 64```

![alt text](https://raw.githubusercontent.com/phrutis/Fialka/main/Others/img/r1.jpg "Fialka M-125")

## Mode 2
### Parallel search WIF with continuation
- **[How to use mode 2 + examples](https://github.com/phrutis/Fialka/blob/main/Others/img/r2.md)**
![alt text](https://raw.githubusercontent.com/phrutis/Fialka/main/Others/img/r2.jpg "Fialka M-125")

## Mode 3-7
## In the process of adding!

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
