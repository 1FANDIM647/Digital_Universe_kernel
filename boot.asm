section.text
      use16
      org 0x7C00
start:
mov ax, cs
mov ds, ax
mov si,a
cld
mov ah, 0x0e
mov bh,0
jmp puts_loop
puts_loop:
  lodsb
    test al , al
    jz text_
    int 10h
    jmp puts_loop
text_
mov ah,0
int 16h
cmp ah,0Eh
jz text_back
mov ah,0x0e
mov bh,0
int 10h
jmp text_
text_back:
mov ah,0x0e
mov bh,0
mov al,8
int 10h
section .data
a db 'Starting Dunix 1.0 ',0