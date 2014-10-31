CC = gcc

binary = billing_validator.o base64.o

billing_validator: $(binary) 
	$(CC) $(binary) --static -lzip -lz -ldl -I/opt/ssl/include/ -L/opt/ssl/lib/ -lcrypto -lm -o $@

billing_validator.o: billing_validator.h

base64.0: base64.h

clean:
	rm -rf *.o billing_validator
