cykel-lock-bl10
===============

This service connects [cykel](https://github.com/stadtulm/cykel) with an Jimi/Concox BL10 Bluetooth/GSM Bike Lock.

## Prerequisites

* Python (≥3.7)

## Installation

Install the required packages using `pip install -r requirements.txt`. It is recommended to use a virtualenv with your choice of tool, e.g. `pipenv`, in which case you can run `pipenv install` (and `pipenv shell` or prefix `pipenv run` to run commands).

## Configuration

cykel-lock-bl10 is configured with environment variables. You may want to create a `.env` file, which you can `source .env` before running `server.py`.

The following envionment variables are needed:
```
export HOST=127.0.0.1
export PORT=8001
export LOCK_HOST=10.0.0.10
export LOCK_PORT=21105
export ENDPOINT="https://<your cykel host>/api/bike/updatelocation"
export ENDPOINT_AUTH_HEADER="Api-Key <your api key for cykel>"
```

`HOST` and `LOCK_HOST` can be two different ip addresses which cykel-lock-bl10 binds to. This can be used to bind the http interface for the communication with cykel only to localhost, if cykel is running on the same machine. 

For the cykel API Key (`ENDPOINT_AUTH_HEADER`), visit your cykel administrative interface and create a new API key.

### Configuration (Lock)
For configuring the lock to use your cykel-lock-bl10 instance, connect your serial/usb adapter and send `AT^GT_CM=SERVER,0,10.0.0.10,21105,0` (see `LOCK_HOST`, `LOCK_PORT` above) or `AT^GT_CM=SERVER,1,lock.hostname.example,21105,0` (if you want to use dns).
