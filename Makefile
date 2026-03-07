CC      := gcc
CFLAGS  := -static -O0 -no-pie
TARGET  := secret
INITRAMFS := initramfs.cpio.gz

all: $(INITRAMFS)

$(TARGET): secret.c
	$(CC) $(CFLAGS) -o $@ $<

$(INITRAMFS): $(TARGET)
	./pack_initramfs.sh $(TARGET) $@

clean:
	rm -f $(TARGET) $(INITRAMFS)

.PHONY: all clean
