# Options

Options are financial derivatives that give
buyers the right, but not the obligation, to buy or sell an underlying asset at
an agreed-upon price and date. These are commonly known as strike price and expiry date.
Similarly, in elements we can create options using covenants and assets. Options can be
created between any two assets, however for simplicity we assume bitcoin-lusd call options.

# Terminology:

- ORT: Options Rights Token, represents the right to exercise the option
- CRT: Collateral Rights Token represents
    - underlying collateral if the option is not executed
    - or settlement amount if the option is exercised.
- ORT-RT: Re-Issuance Token for ORT
- CRT-RT: Re-Issuance Token for CRT

# Usage:

1) Build a version of elementsd which has the partial blinding bug fixed.
2) ELEMENTSD_EXE=~/elements/src/elementsd cargo test to run the test scenario described below

## Test scenario

- Issues CRT/ORT RT tokens with 1 amount to RT covenant
- Fund the covenant by issuing 10 contracts locking the collateral
- Exercise 3 of 10 contracts
- Cancellation of 4 of remaining 7 contracts
- Expire the remaining 4 contracts(no change case)

Claim the settlment in two steps.

- Claim 1 contract (change case)
- Claim the remaining 2 contracts (no change case)