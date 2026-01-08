SPEED = 2097152
PORT = /dev/ttyUSB0
SECRET = sadfhj9283ru982iwuh*?sdf_12-3ddq

client:
	python3 client/main.py $(PORT):$(SPEED) $(SECRET)

server:
	cd server; \
	export PLATFORMIO_BUILD_FLAGS="-DSPEED=\\\"$(SPEED)\\\" -DSECRET=\\\"$(SECRET)\\\""; \
	pio run -t upload

install:
	pip3 install python-mbedtls pyserial PyQt6

clean:
	rm -rf server/.pio server/.vscode client/__pycache__

.PHONY: client server install
