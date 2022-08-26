# Options

Options are financial derivatives that give
buyers the right, but not the obligation, to buy or sell an underlying asset at
an agreed-upon price and date. These are commonly known as strike price and expiry date.
Similarly, in elements we can create options using covenants and assets. Options can be
created between any two assets, however for simplicity we assume bitcoin-lusd call options.

# Components:

## Options-lib:
    The underlying code for options library with covenant logic and pset interface

## Options Client(opt-cli)
    The client that operates with elementsd wallet to interact with the options
# Terminology:

- ORT: Options Rights Token, represents the right to exercise the option
- CRT: Collateral Rights Token represents
    - underlying collateral if the option is not executed
    - or settlement amount if the option is exercised.
- ORT-RT: Re-Issuance Token for ORT
- CRT-RT: Re-Issuance Token for CRT

# Client Usage:

- Change directory to `src/client`
- Optionally Install the client locally with `cargo install --path .` This would install the application locally, otherwise
you can build it temporarily using `cargo build` and run it from `/target/debug/opt-cli`
- By default, the client looks for elementsd config `$HOME/liquidtestnet`. This can be changed using the `--datadir` option
- Elements should have atleast one wallet loaded.

## Tool demo:

```
opt-cli initialize --contract-size=1000 --expiry=1661544383 --start=1661544383 --strike-price=100000 --coll-asset=4a75e0dffa7c677e3b18e5570f146cc8cffb201a4fac0e9f7e17ec3cb9082934 --settle-asset=1adc82a9ed873619987cc24cfabbc1c43a5c4078b4a76b14d603c46769031512
Contract Id: d467c3ff41ebe998a6012da517cd3307af7ff0f168d1ddf9dda81b09c7477df1
Issue txid: c90986b9aabec5a281bad4c84ea7ab1d3192748a52ea9637d71d831fb17cc9f2
```
This outputs a contract id that should be used when interacting with this contract in future. You can always see --help for more help

Funding the contract:

```
opt-cli fund -n=2 -c=d467c3ff41ebe998a6012da517cd3307af7ff0f168d1ddf9dda81b09c7477df1
Contract Id: d467c3ff41ebe998a6012da517cd3307af7ff0f168d1ddf9dda81b09c7477df1
Funding txid: 44ff85f2f12c796208f612f102a36d4b26483fc406194d232aba3ea085188ec5
```

Exercise
```
opt-cli exercise -n=1 -c=d467c3ff41ebe998a6012da517cd3307af7ff0f168d1ddf9dda81b09c7477df1
Contract Id: d467c3ff41ebe998a6012da517cd3307af7ff0f168d1ddf9dda81b09c7477df1
Exercise txid: 41d72a02777e2fb1267f71a9fe5519766a799f3af49b853e5043b541521375b6
```

Expiry:

```
opt-cli expiry -n=1 -c=d467c3ff41ebe998a6012da517cd3307af7ff0f168d1ddf9dda81b09c7477df1
Contract Id: d467c3ff41ebe998a6012da517cd3307af7ff0f168d1ddf9dda81b09c7477df1
Expiry txid: a17d0077949683fd868393f82102cd742c885bc08c45093fecaf7f75c31292da
```

Cancel:

```
opt-cli cancel -n=1 -c=d467c3ff41ebe998a6012da517cd3307af7ff0f168d1ddf9dda81b09c7477df1
Contract Id: d467c3ff41ebe998a6012da517cd3307af7ff0f168d1ddf9dda81b09c7477df1
Cancel txid: 47ce2678aaa0def2cde5dbb9a2fb0605966a49dd0652780de500e2d096e333ee
```

Settlement:

```
opt-cli settle -n=1 -c=d467c3ff41ebe998a6012da517cd3307af7ff0f168d1ddf9dda81b09c7477df1
Contract Id: d467c3ff41ebe998a6012da517cd3307af7ff0f168d1ddf9dda81b09c7477df1
Settle txid: 60d334602d21b778b14c7109373198a9201390d8cb28b3a7a95834736db47927
```


## Unit Test scenario

- Issues CRT/ORT RT tokens with 1 amount to RT covenant
- Fund the covenant by issuing 10 contracts locking the collateral
- Exercise 3 of 10 contracts
- Cancellation of 4 of remaining 7 contracts
- Expire the remaining 4 contracts(no change case)

Claim the settlment in two steps.

- Claim 1 contract (change case)
- Claim the remaining 2 contracts (no change case)