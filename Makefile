CC=gcc
CFLAGS=-O2 -Wall

AS=as
ASFLAGS=--64

LD=ld
LDFLAGS=-m elf_x86_64

TARGET=pasm
TARGETFLAGS=asm.s -o pasm_out.o

.PHONY: all run clean

all: $(TARGET) gas_out run

$(TARGET): pasm.c
	$(CC) $(CFLAGS) -o $@ $^

gas_out: asm.s
	$(AS) $(ASFLAGS) $< -o $@.o && $(LD) $(LDFLAGS) $@.o -o $@

run:
	./$(TARGET) $(TARGETFLAGS) && $(LD) $(LDFLAGS) $(TARGET)_out.o -o $(TARGET)_out

clean:
	rm $(TARGET)
