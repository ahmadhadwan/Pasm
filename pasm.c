/*
 * Pasm, Pixie (elf) Assembler, is an Elf64 x86_64 assembler.
 * Copyright (C) 2022 Ahmad Hadwan
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; See COPYING file for copyright and license details.
 */
#include <ctype.h>
#include <elf.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#define OUTFILE_DEFAULT "a.out"

/* enums */
enum { UNKNOWN, INS, LABEL, DIRECTIVE, CONSTANT, REGISTER, COMMA };

/* structs */
typedef struct {
    Elf64_Ehdr *ehdr;
    uint8_t    *assembly;
    size_t      assembly_size;
    Elf64_Sym  *syms;
    size_t      section_count;
    size_t      label_count;
    size_t      glabel_count;
    char      **strtab;
    size_t      strtab_count;
    char      **shstrtab;
    size_t      shstrtab_count;
    Elf64_Shdr *shdrs;
    size_t      shdr_count;
} elf64_obj_t;

typedef struct {
    int    type;
    int    len;
    size_t start;
} token_t;

typedef struct {
    char  *src;
    size_t i;
} unit_t;

/* function declarations */
static int assemble_file(char *filename, char *outfile);
static int assemble_x86_64(char *src, char *outfile);
static int default_shdrtabs_x86_64(elf64_obj_t *obj);
static int default_symtabs_x86_64(elf64_obj_t *obj);
static int lex(unit_t *unit, token_t *token);
static int parse_x86_64(unit_t *unit, elf64_obj_t *obj);
static void usage();
static int write_file_x86_64(char *outfile, elf64_obj_t *obj);

/* variables */
/* temp */
static const char shstrtab[] = "\0.symtab\0.strtab\0.shstrtab\0.text\0.data\0.bss\0\0\0\0\0";
static uint8_t exit_assembly[] = {
    0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00,
    0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00,
    0x0F, 0x05
};
static const size_t exit_assembly_len = 16;

/* function implementations */
int assemble_file(char *filename, char *outfile)
{
    FILE *fd;
    struct stat filestat;
    char *src;
    int return_value;

    fd = fopen(filename, "r");
    if (fd == NULL) {
        fprintf(stderr, "Failed to open `%s`.\n", filename);
        return 1;
    }

    if (stat(filename, &filestat)) {
        fprintf(stderr, "Failed to stat `%s`.\n", filename);
        return 1;
    }

    src = malloc(filestat.st_size + 1);
    src[filestat.st_size] = '\0';
    fread(src, sizeof(char), filestat.st_size, fd);
    fclose(fd);

    return_value = assemble_x86_64(src, outfile);

    free(src);
    return return_value;
}

int assemble_x86_64(char *src, char *outfile)
{
    elf64_obj_t obj;
    Elf64_Ehdr ehdr;
    unit_t unit;

    obj = (elf64_obj_t){
        .strtab = malloc(sizeof(char *)), .shstrtab = malloc(sizeof(char *))
    };
    obj.strtab[0] = NULL;
    obj.shstrtab[0] = NULL;
    unit = (unit_t){ .src = src, .i = 0 };

    default_symtabs_x86_64(&obj);

    if (parse_x86_64(&unit, &obj)) {
        return 1;
    }

    ehdr = (Elf64_Ehdr){
        .e_ident[EI_MAG0] = ELFMAG0, .e_ident[EI_MAG1] = ELFMAG1,
        .e_ident[EI_MAG2] = ELFMAG2, .e_ident[EI_MAG3] = ELFMAG3,
        .e_ident[EI_CLASS] = ELFCLASS64, .e_ident[EI_DATA] = ELFDATA2LSB,
        .e_ident[EI_VERSION] = EV_CURRENT, .e_ident[EI_OSABI] = ELFOSABI_SYSV,
        .e_ident[EI_ABIVERSION] = 0,
        .e_type = ET_REL, /* Object File | TODO: add executables support later */
        .e_machine = EM_X86_64, .e_version = EV_CURRENT, .e_entry = 0,
        .e_phoff = 0, .e_shoff = 240 + obj.assembly_size, .e_flags = 0,
        .e_ehsize = sizeof(Elf64_Ehdr), .e_phentsize = 0, .e_phnum = 0,
        .e_shentsize = 64, .e_shnum = 7, .e_shstrndx = 6
    };

    obj.ehdr = &ehdr;

    default_shdrtabs_x86_64(&obj);
    write_file_x86_64(outfile, &obj);

    free(obj.syms);
    free(obj.shdrs);

    for (int i = 0; i < obj.strtab_count; i++) {
        free(obj.strtab[i]);
    }
    free(obj.strtab);

    for (int i = 0; i < obj.shstrtab_count; i++) {
        free(obj.shstrtab[i]);
    }
    free(obj.shstrtab);

    return 0;
}

int default_shdrtabs_x86_64(elf64_obj_t *obj)
{
    Elf64_Shdr shdr_null, shdr_text, shdr_data, shdr_bss,
               shdr_symtab, shdr_strtab, shdr_shstrtab;
    size_t sh_offset;
    sh_offset = sizeof(Elf64_Ehdr);

    shdr_null = (Elf64_Shdr){};

    shdr_text = (Elf64_Shdr){
        .sh_name = 0x1b, .sh_type = SHT_PROGBITS,
        .sh_flags = SHF_ALLOC | SHF_EXECINSTR, .sh_addr = 0,
        .sh_offset = sh_offset, .sh_size = obj->assembly_size, .sh_link = 0,
        .sh_info = 0, .sh_addralign = 1, .sh_entsize = 0
    };
    sh_offset += shdr_text.sh_size;

    shdr_data = (Elf64_Shdr){
        .sh_name = 0x21, .sh_type = SHT_PROGBITS,
        .sh_flags = SHF_ALLOC | SHF_WRITE, .sh_addr = 0,
        .sh_offset = sh_offset, .sh_size = 0x0, .sh_link = 0, .sh_info = 0,
        .sh_addralign = 1, .sh_entsize = 0
    };
    sh_offset += shdr_data.sh_size;

    shdr_bss = (Elf64_Shdr){
        .sh_name = 0x27, .sh_type = SHT_NOBITS,
        .sh_flags = SHF_ALLOC | SHF_WRITE, .sh_addr = 0,
        .sh_offset = sh_offset, .sh_size = 0x0, .sh_link = 0, .sh_info = 0,
        .sh_addralign = 1, .sh_entsize = 0
    };
    sh_offset += shdr_bss.sh_size;

    shdr_symtab = (Elf64_Shdr){
        .sh_name = 0x01, .sh_type = SHT_SYMTAB, .sh_flags = 0, .sh_addr = 0,
        .sh_offset = sh_offset, .sh_size = sizeof(Elf64_Sym) * 5, .sh_link = 5,
        .sh_info = obj->section_count + obj->label_count, /* The number of LOCAL symtabs */
        .sh_addralign = 8, .sh_entsize = 0x18
    };
    sh_offset += shdr_symtab.sh_size;

    shdr_strtab = (Elf64_Shdr){
        .sh_name = 0x09, .sh_type = SHT_STRTAB, .sh_flags = 0, .sh_addr = 0,
        .sh_offset = sh_offset, .sh_size = sizeof(strtab) - 1, .sh_link = 0,
        .sh_info = 0, .sh_addralign = 1, .sh_entsize = 0
    };
    sh_offset += shdr_strtab.sh_size;

    shdr_shstrtab = (Elf64_Shdr){
        .sh_name = 0x11, .sh_type = SHT_STRTAB, .sh_flags = 0,
        .sh_addr = 0, .sh_offset = sh_offset,
        .sh_size = sizeof(shstrtab) - 1 -4/* the padded zeros */,
        .sh_link = 0, .sh_info = 0, .sh_addralign = 1, .sh_entsize = 0
    };
    sh_offset += shdr_shstrtab.sh_size;

    obj->shdrs = malloc(7 * sizeof(Elf64_Shdr));
    memcpy(&(obj->shdrs[0]), &shdr_null, sizeof(Elf64_Shdr));
    memcpy(&(obj->shdrs[1]), &shdr_text, sizeof(Elf64_Shdr));
    memcpy(&(obj->shdrs[2]), &shdr_data, sizeof(Elf64_Shdr));
    memcpy(&(obj->shdrs[3]), &shdr_bss, sizeof(Elf64_Shdr));
    memcpy(&(obj->shdrs[4]), &shdr_symtab, sizeof(Elf64_Shdr));
    memcpy(&(obj->shdrs[5]), &shdr_strtab, sizeof(Elf64_Shdr));
    memcpy(&(obj->shdrs[6]), &shdr_shstrtab, sizeof(Elf64_Shdr));

    obj->shdr_count += 7;
    return 0;
}

int default_symtabs_x86_64(elf64_obj_t *obj)
{
    Elf64_Sym sym_null, sym_text, sym_data, sym_bss;

    sym_null = (Elf64_Sym){};

    sym_text = (Elf64_Sym){
        .st_name = 0, .st_info = ELF64_ST_INFO(STB_LOCAL, STT_SECTION),
        .st_other = STV_DEFAULT, .st_shndx = 1, .st_value = 0, .st_size = 0
    };

    sym_data = (Elf64_Sym){
        .st_name = 0, .st_info = ELF64_ST_INFO(STB_LOCAL, STT_SECTION),
        .st_other = STV_DEFAULT, .st_shndx = 2, .st_value = 0, .st_size = 0
    };

    sym_bss = (Elf64_Sym){
        .st_name = 0, .st_info = ELF64_ST_INFO(STB_LOCAL, STT_SECTION),
        .st_other = STV_DEFAULT, .st_shndx = 3, .st_value = 0, .st_size = 0
    };

    obj->syms = malloc(4 * sizeof(Elf64_Sym));
    memcpy(&(obj->syms[0]), &sym_null, sizeof(Elf64_Sym));
    memcpy(&(obj->syms[1]), &sym_text, sizeof(Elf64_Sym));
    memcpy(&(obj->syms[2]), &sym_data, sizeof(Elf64_Sym));
    memcpy(&(obj->syms[3]), &sym_bss, sizeof(Elf64_Sym));

    obj->section_count += 4;
    return 0;
}

int lex(unit_t *unit, token_t *token)
{
    token->type = UNKNOWN;

    do {
        while (isspace(unit->src[unit->i])) {
            unit->i++;
        }

        if (unit->src[unit->i] == ';') {
            do {
                unit->i++;
            } while (unit->src[unit->i] != '\n' && unit->src[unit->i] != '\0');
        }
    } while (isspace(unit->src[unit->i]));

    token->start = unit->i;
    token->len = 0;

    if (unit->src[unit->i] == '.') {
        unit->i++;
    }
    else if (unit->src[unit->i] == '_' || isalpha(unit->src[unit->i])) {
        unit->i++;
        while (unit->src[unit->i] == '_' || isalnum(unit->src[unit->i])) {
            unit->i++;
        }

        if (unit->src[unit->i] == ':') {
            token->type = LABEL;
            token->len = unit->i - token->start;
            unit->i++;
        }
    }
    else if (unit->src[unit->i] == '\0') {
        return 1;
    }
    else {
        fprintf(stderr, "Invalid character `%c` in mnemonic.\n", unit->src[unit->i]);
        return 1;
    }

    return 0;
}

int parse_x86_64(unit_t *unit, elf64_obj_t *obj)
{
    token_t token;
    char *buff;

    while (!lex(unit, &token)) {
        buff = malloc(token.len + 1);
        memcpy(buff, unit->src + token.start, token.len);
        buff[token.len] = '\0';

        printf("token: type=%d, text=%s\n", token.type, buff);

        switch (token.type)
        {
            case LABEL:
            {
                size_t syms_index = obj->section_count + obj->label_count
                                  + obj->glabel_count;
                obj->syms = realloc(obj->syms,
                                    (syms_index + 1) * sizeof(Elf64_Sym));
                obj->syms[syms_index] = (Elf64_Sym){
                    .st_name = 0x01,
                    .st_info = ELF64_ST_INFO(STB_LOCAL, STT_NOTYPE),
                    .st_other = STV_DEFAULT, .st_shndx = obj->label_count + 1,
                    .st_value = 0, .st_size = 0
                };

                obj->strtab = realloc(obj->strtab,
                                     (obj->strtab_count + 1) * sizeof(char *));
                obj->strtab[obj->strtab_count] = buff;
                obj->strtab[obj->strtab_count] = buff;

                obj->strtab_count++;
                obj->label_count++;
                break;
            }
            default:
                free(buff);
                break;
        }
    }

    /* temp */
    obj->assembly = malloc(exit_assembly_len);
    memcpy(obj->assembly, exit_assembly, exit_assembly_len);
    obj->assembly_size = exit_assembly_len;

    return 0;
}

void usage()
{
    puts("Usage: pasm [options] asmfile\n"
         "Options:\n"
         "  --help      Display this information.\n"
         "  -o OUTFILE  Specify the output file name. (default is "OUTFILE_DEFAULT")"
    );
}

int write_file_x86_64(char *outfile, elf64_obj_t *obj)
{
    uint8_t *raw_obj;
    size_t raw_obj_len, syms_count, strtab_len;
    FILE *fd;

    syms_count = obj->section_count + obj->label_count + obj->glabel_count;

    strtab_len = 1; /* first zero */
    for (int i = 0; i < obj->strtab_count; i++) {
        strtab_len += strlen(obj->strtab[i]) + 1;
    }

    raw_obj = malloc(sizeof(Elf64_Ehdr) + obj->assembly_size
                     + (sizeof(Elf64_Sym) * syms_count)
                     + strtab_len
                     + sizeof(shstrtab) - 1
                     + (sizeof(Elf64_Shdr) * obj->shdr_count)
    );
    raw_obj_len = 0;
    memcpy(raw_obj, obj->ehdr, sizeof(Elf64_Ehdr));
    raw_obj_len += sizeof(Elf64_Ehdr);

    if (obj->assembly) {
        memcpy(raw_obj + raw_obj_len, obj->assembly, obj->assembly_size);
        raw_obj_len += obj->assembly_size;
        free(obj->assembly);
    }

    for (int i = 0; i < syms_count; i++) {
        memcpy(raw_obj + raw_obj_len, &(obj->syms[i]), sizeof(Elf64_Sym));
        raw_obj_len += sizeof(Elf64_Sym);
    }

    raw_obj[raw_obj_len] = '\0';
    raw_obj_len++;
    for (int i = 0; i < obj->strtab_count; i++) {
        size_t current_str_len = strlen(obj->strtab[i]) + 1;
        memcpy(raw_obj + raw_obj_len, obj->strtab[i], current_str_len);
        raw_obj_len += current_str_len;
    }

    memcpy(raw_obj + raw_obj_len, shstrtab, sizeof(shstrtab) - 1);
    raw_obj_len += sizeof(shstrtab) - 1;

    for (int i = 0; i < obj->shdr_count; i++) {
        memcpy(raw_obj + raw_obj_len, &(obj->shdrs[i]), sizeof(Elf64_Shdr));
        raw_obj_len += sizeof(Elf64_Shdr);
    }

    fd = fopen(outfile, "w");
    fwrite(raw_obj, raw_obj_len, 1, fd);
    fclose(fd);

    free(raw_obj);
    return 0;
}

int main(int argc, char **argv)
{
    char *filename, *outfile;

    filename = outfile = NULL;

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            if (!strcmp(argv[i], "--help")) {
                usage();
                return 0;
            }
            else if (!strcmp(argv[i], "-o")) {
                i++;

                if (outfile) {
                    fprintf(stderr, "Output file name was already specified!\n");
                    return 1;
                }

                if (i >= argc) {
                    fprintf(stderr, "Option `-o` requires an argument.\n");
                    return 1;
                }

                outfile = argv[i];
            }
            else {
                usage();
                return 1;
            }
        }
        else {
            if (filename) {
                fprintf(stderr, "Pasm currently doesn't support multiple files as input!\n");
                return 1;
            }
            filename = argv[i];
        }
    }

    if (!filename) {
        fprintf(stderr, "pasm: fatal error: no input files.\n");
        return 1;
    }

    if (!outfile) {
        outfile = OUTFILE_DEFAULT;
    }

    return assemble_file(filename, outfile);
}
