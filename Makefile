cap: packetcap.c
	gcc $^ -o $@ -lpcap

clean:
	rm -rf *.o cap
