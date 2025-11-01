#include "pisa/pisa.h"
#include <stdlib.h>
#include <string.h>

bool pisa_program_add_inst(pisa_program_t *pgm, pisa_inst_t *inst) {
  pgm->insts = (pisa_inst_t *)realloc(pgm->insts, sizeof(pisa_inst_t) *
                                                      (pgm->inst_count + 1));
  pgm->insts[pgm->inst_count] = *inst;
  pgm->inst_count++;

  return true;
}

bool pisa_program_add_meta_inst(pisa_program_t *pgm, const char *key,
                                pisa_value_t value) {

  pisa_inst_t meta_inst;

  meta_inst.op = SET_META;

  size_t keylen = strlen(key) + 1;
  char *lkey = (char *)calloc(keylen, sizeof(char));
  memcpy(lkey, key, keylen);
  meta_inst.fk.key.data = (uint8_t *)lkey;
  meta_inst.fk.key.len = keylen;
  meta_inst.value = value;

  return pisa_program_add_inst(pgm, &meta_inst);
}

bool pisa_program_rem_inst(pisa_program_t *pgm, size_t pc) { return false; }

bool pisa_program_find_inst(pisa_program_t *pgm, pisa_inst_t *inst,
                            size_t *pc) {
  return false;
}

pisa_program_t *pisa_program_new() { return calloc(1, sizeof(pisa_program_t)); }

bool pisa_program_find_field_value(pisa_program_t *pgm, pisa_field_t field,
                                   pisa_value_t *value) {
  for (size_t indx = 0; indx < pgm->inst_count; indx++) {
    pisa_inst_t *inst = &pgm->insts[pgm->inst_count - 1 - indx];
    if (inst->op == SET_FIELD && inst->fk.field == field) {
      *value = inst->value;
      return true;
    }
  }
  return false;
}

bool pisa_program_find_meta_value(pisa_program_t *pgm, const char *key,
                                  pisa_value_t *value) {
  if (value->tpe == UNKNOWN) {
    return false;
  }

  for (size_t indx = 0; indx < pgm->inst_count; indx++) {
    pisa_inst_t *inst = &pgm->insts[pgm->inst_count - 1 - indx];
    if (inst->op == SET_META && value->tpe == inst->value.tpe &&
        !strcmp((char *)inst->fk.key.data, key)) {
      *value = inst->value;
      return true;
    }
  }
  return false;
}

bool pisa_program_find_target_value(pisa_program_t *pgm, pisa_value_t *value) {
  // First, find the destination. The program must set one.
  if (!pisa_program_find_field_value(pgm, IPV4_TARGET, value) &&
      !pisa_program_find_field_value(pgm, IPV6_TARGET, value)) {
    return false;
  }

  return true;
}

bool pisa_program_find_target_family(pisa_program_t *pgm, uint8_t *family) {
  pisa_value_t pisa_target;
  if (pisa_program_find_target_value(pgm, &pisa_target)) {
    *family = pisa_target.value.ipaddr.family;
    return true;
  }
  return false;
}

const char *__pisa_field_names[] = {
    "IPV4_TTL",
    "IPV6_HL",
    "IPV4_TARGET",
    "IPV6_TARGET",
    "IPV4_ECN",
    "IPV6_ECN",
    "IPV4_DSCP",
    "IPV6_DSCP",
    "BODY",
};

const char *pisa_field_name(pisa_field_t field) {
  if (field < PISA_FIELD_MAX) {
    return __pisa_field_names[field];
  }
  return NULL;
}

const char *__pisa_opcode_names[] = {
    "SET_META",
    "SET_FIELD",
    "SET_OFFSET",
};

const char *pisa_opcode_name(pisa_opcode_t opcode) {
  if (opcode < PISA_OPCODE_MAX) {
    return __pisa_opcode_names[opcode];
  }
  return NULL;
}

void pisa_value_release(pisa_value_t *value) {
  if (value->tpe == PTR && value->value.ptr.len != 0) {
    free(value->value.ptr.data);
  }
}

void pisa_instruction_release(pisa_inst_t *inst) {
  // We only release values that are from SET_META. Everyone
  // else is on their own!
  if (inst->op == SET_META) {
    pisa_value_release(&inst->value);
    if (inst->fk.key.len != 0) {
      free(inst->fk.key.data);
      inst->fk.key.len = 0;
      inst->fk.key.data = NULL;
    }
  }
}

void pisa_program_release(pisa_program_t *program) {
  for (size_t indx = 0; indx < program->inst_count; indx++) {
    pisa_instruction_release(&program->insts[indx]);
  }
  free(program->insts);
  free(program);
}