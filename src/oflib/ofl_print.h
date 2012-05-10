/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#ifndef OFL_PRINT_H
#define OFL_PRINT_H 1

#include <sys/types.h>
#include <inttypes.h>
#include <stdio.h>
#include <openflow/openflow.h>
#include "ofl.h"
#include "ofl_print.h"


/****************************************************************************
 * Functions for printing enum values
 ****************************************************************************/

char *
ofl_port_to_string(uint32_t port);

void
ofl_port_print(FILE *stream, uint32_t port);

char *
ofl_queue_to_string(uint32_t queue);

void
ofl_queue_print(FILE *stream, uint32_t queue);

char *
ofl_group_to_string(uint32_t group);

void
ofl_group_print(FILE *stream, uint32_t group);

char *
ofl_table_to_string(uint8_t table);

void
ofl_table_print(FILE *stream, uint8_t table);

char *
ofl_vlan_vid_to_string(uint32_t vid);

void
ofl_vlan_vid_print(FILE *stream, uint32_t vid);

char *
ofl_action_type_to_string(uint16_t type);

void
ofl_action_type_print(FILE *stream, uint16_t type);

char *
ofl_instruction_type_to_string(uint16_t type);

void
ofl_instruction_type_print(FILE *stream, uint16_t type);

char *
ofl_queue_prop_type_to_string(uint16_t type);

void
ofl_queue_prop_type_print(FILE *stream, uint16_t type);

char *
ofl_error_type_to_string(uint16_t type);

void
ofl_error_type_print(FILE *stream, uint16_t type);

char *
ofl_error_code_to_string(uint16_t type, uint16_t code);

void
ofl_error_code_print(FILE *stream, uint16_t type, uint16_t code);

char *
ofl_message_type_to_string(uint16_t type);

void
ofl_message_type_print(FILE *stream, uint16_t type);

char *
ofl_buffer_to_string(uint32_t buffer);

void
ofl_buffer_print(FILE *stream, uint32_t buffer);

char *
ofl_packet_in_reason_to_string(uint8_t reason);

void
ofl_packet_in_reason_print(FILE *stream, uint8_t reason);

char *
ofl_flow_removed_reason_to_string(uint8_t reason);

void
ofl_flow_removed_reason_print(FILE *stream, uint8_t reason);

char *
ofl_port_status_reason_to_string(uint8_t reason);

void
ofl_port_status_reason_print(FILE *stream, uint8_t reason);

char *
ofl_flow_mod_command_to_string(uint8_t command);

void
ofl_flow_mod_command_print(FILE *stream, uint8_t command);

char *
ofl_group_mod_command_to_string(uint16_t command);

void
ofl_group_mod_command_print(FILE *stream, uint16_t command);

char *
ofl_group_type_to_string(uint8_t type);

void
ofl_group_type_print(FILE *stream, uint8_t type);

char *
ofl_stats_type_to_string(uint16_t type);

void
ofl_stats_type_print(FILE *stream, uint16_t type);

char *
ofl_hex_to_string(uint8_t *buf, size_t buf_size);

void
ofl_hex_print(FILE *stream, uint8_t *buf, size_t buf_size);

#endif /* OFL_PRINT_H */
