// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later
// Generated by scripts/gen_dwarf_constants.py.

/**
 * @file
 *
 * DWARF constant definitions.
 *
 * This file defines the following for each known DWARF constant type:
 *
 * 1. An X macro defining all of the known names and values of the type:
 *    `DW_FOO_DEFINITIONS`.
 * 2. Enumerators defining the constants: `DW_FOO_a`, `DW_FOO_b`, etc.
 * 3. For select types, a function to translate a value to its name:
 *   `dw_foo_str()`.
 */

#ifndef DWARF_CONSTANTS_H
#define DWARF_CONSTANTS_H

#define X(name, value) name = value,

#define DW_ACCESS_DEFINITIONS \
	X(DW_ACCESS_public, 0x1) \
	X(DW_ACCESS_protected, 0x2) \
	X(DW_ACCESS_private, 0x3)
enum { DW_ACCESS_DEFINITIONS };

#define DW_ADDR_DEFINITIONS \
	X(DW_ADDR_none, 0x0)
enum { DW_ADDR_DEFINITIONS };

#define DW_AT_DEFINITIONS \
	X(DW_AT_sibling, 0x1) \
	X(DW_AT_location, 0x2) \
	X(DW_AT_name, 0x3) \
	X(DW_AT_ordering, 0x9) \
	X(DW_AT_subscr_data, 0xa) \
	X(DW_AT_byte_size, 0xb) \
	X(DW_AT_bit_offset, 0xc) \
	X(DW_AT_bit_size, 0xd) \
	X(DW_AT_element_list, 0xf) \
	X(DW_AT_stmt_list, 0x10) \
	X(DW_AT_low_pc, 0x11) \
	X(DW_AT_high_pc, 0x12) \
	X(DW_AT_language, 0x13) \
	X(DW_AT_member, 0x14) \
	X(DW_AT_discr, 0x15) \
	X(DW_AT_discr_value, 0x16) \
	X(DW_AT_visibility, 0x17) \
	X(DW_AT_import, 0x18) \
	X(DW_AT_string_length, 0x19) \
	X(DW_AT_common_reference, 0x1a) \
	X(DW_AT_comp_dir, 0x1b) \
	X(DW_AT_const_value, 0x1c) \
	X(DW_AT_containing_type, 0x1d) \
	X(DW_AT_default_value, 0x1e) \
	X(DW_AT_inline, 0x20) \
	X(DW_AT_is_optional, 0x21) \
	X(DW_AT_lower_bound, 0x22) \
	X(DW_AT_producer, 0x25) \
	X(DW_AT_prototyped, 0x27) \
	X(DW_AT_return_addr, 0x2a) \
	X(DW_AT_start_scope, 0x2c) \
	X(DW_AT_bit_stride, 0x2e) \
	X(DW_AT_stride_size, 0x2e) \
	X(DW_AT_upper_bound, 0x2f) \
	X(DW_AT_abstract_origin, 0x31) \
	X(DW_AT_accessibility, 0x32) \
	X(DW_AT_address_class, 0x33) \
	X(DW_AT_artificial, 0x34) \
	X(DW_AT_base_types, 0x35) \
	X(DW_AT_calling_convention, 0x36) \
	X(DW_AT_count, 0x37) \
	X(DW_AT_data_member_location, 0x38) \
	X(DW_AT_decl_column, 0x39) \
	X(DW_AT_decl_file, 0x3a) \
	X(DW_AT_decl_line, 0x3b) \
	X(DW_AT_declaration, 0x3c) \
	X(DW_AT_discr_list, 0x3d) \
	X(DW_AT_encoding, 0x3e) \
	X(DW_AT_external, 0x3f) \
	X(DW_AT_frame_base, 0x40) \
	X(DW_AT_friend, 0x41) \
	X(DW_AT_identifier_case, 0x42) \
	X(DW_AT_macro_info, 0x43) \
	X(DW_AT_namelist_item, 0x44) \
	X(DW_AT_priority, 0x45) \
	X(DW_AT_segment, 0x46) \
	X(DW_AT_specification, 0x47) \
	X(DW_AT_static_link, 0x48) \
	X(DW_AT_type, 0x49) \
	X(DW_AT_use_location, 0x4a) \
	X(DW_AT_variable_parameter, 0x4b) \
	X(DW_AT_virtuality, 0x4c) \
	X(DW_AT_vtable_elem_location, 0x4d) \
	X(DW_AT_allocated, 0x4e) \
	X(DW_AT_associated, 0x4f) \
	X(DW_AT_data_location, 0x50) \
	X(DW_AT_byte_stride, 0x51) \
	X(DW_AT_entry_pc, 0x52) \
	X(DW_AT_use_UTF8, 0x53) \
	X(DW_AT_extension, 0x54) \
	X(DW_AT_ranges, 0x55) \
	X(DW_AT_trampoline, 0x56) \
	X(DW_AT_call_column, 0x57) \
	X(DW_AT_call_file, 0x58) \
	X(DW_AT_call_line, 0x59) \
	X(DW_AT_description, 0x5a) \
	X(DW_AT_binary_scale, 0x5b) \
	X(DW_AT_decimal_scale, 0x5c) \
	X(DW_AT_small, 0x5d) \
	X(DW_AT_decimal_sign, 0x5e) \
	X(DW_AT_digit_count, 0x5f) \
	X(DW_AT_picture_string, 0x60) \
	X(DW_AT_mutable, 0x61) \
	X(DW_AT_threads_scaled, 0x62) \
	X(DW_AT_explicit, 0x63) \
	X(DW_AT_object_pointer, 0x64) \
	X(DW_AT_endianity, 0x65) \
	X(DW_AT_elemental, 0x66) \
	X(DW_AT_pure, 0x67) \
	X(DW_AT_recursive, 0x68) \
	X(DW_AT_signature, 0x69) \
	X(DW_AT_main_subprogram, 0x6a) \
	X(DW_AT_data_bit_offset, 0x6b) \
	X(DW_AT_const_expr, 0x6c) \
	X(DW_AT_enum_class, 0x6d) \
	X(DW_AT_linkage_name, 0x6e) \
	X(DW_AT_string_length_bit_size, 0x6f) \
	X(DW_AT_string_length_byte_size, 0x70) \
	X(DW_AT_rank, 0x71) \
	X(DW_AT_str_offsets_base, 0x72) \
	X(DW_AT_addr_base, 0x73) \
	X(DW_AT_rnglists_base, 0x74) \
	X(DW_AT_dwo_id, 0x75) \
	X(DW_AT_dwo_name, 0x76) \
	X(DW_AT_reference, 0x77) \
	X(DW_AT_rvalue_reference, 0x78) \
	X(DW_AT_macros, 0x79) \
	X(DW_AT_call_all_calls, 0x7a) \
	X(DW_AT_call_all_source_calls, 0x7b) \
	X(DW_AT_call_all_tail_calls, 0x7c) \
	X(DW_AT_call_return_pc, 0x7d) \
	X(DW_AT_call_value, 0x7e) \
	X(DW_AT_call_origin, 0x7f) \
	X(DW_AT_call_parameter, 0x80) \
	X(DW_AT_call_pc, 0x81) \
	X(DW_AT_call_tail_call, 0x82) \
	X(DW_AT_call_target, 0x83) \
	X(DW_AT_call_target_clobbered, 0x84) \
	X(DW_AT_call_data_location, 0x85) \
	X(DW_AT_call_data_value, 0x86) \
	X(DW_AT_noreturn, 0x87) \
	X(DW_AT_alignment, 0x88) \
	X(DW_AT_export_symbols, 0x89) \
	X(DW_AT_deleted, 0x8a) \
	X(DW_AT_defaulted, 0x8b) \
	X(DW_AT_loclists_base, 0x8c) \
	X(DW_AT_ghs_namespace_alias, 0x806) \
	X(DW_AT_ghs_using_namespace, 0x807) \
	X(DW_AT_ghs_using_declaration, 0x808) \
	X(DW_AT_HP_block_index, 0x2000) \
	X(DW_AT_lo_user, 0x2000) \
	X(DW_AT_MIPS_fde, 0x2001) \
	X(DW_AT_MIPS_loop_begin, 0x2002) \
	X(DW_AT_MIPS_tail_loop_begin, 0x2003) \
	X(DW_AT_MIPS_epilog_begin, 0x2004) \
	X(DW_AT_MIPS_loop_unroll_factor, 0x2005) \
	X(DW_AT_MIPS_software_pipeline_depth, 0x2006) \
	X(DW_AT_MIPS_linkage_name, 0x2007) \
	X(DW_AT_MIPS_stride, 0x2008) \
	X(DW_AT_MIPS_abstract_name, 0x2009) \
	X(DW_AT_MIPS_clone_origin, 0x200a) \
	X(DW_AT_MIPS_has_inlines, 0x200b) \
	X(DW_AT_MIPS_stride_byte, 0x200c) \
	X(DW_AT_MIPS_stride_elem, 0x200d) \
	X(DW_AT_MIPS_ptr_dopetype, 0x200e) \
	X(DW_AT_MIPS_allocatable_dopetype, 0x200f) \
	X(DW_AT_MIPS_assumed_shape_dopetype, 0x2010) \
	X(DW_AT_MIPS_assumed_size, 0x2011) \
	X(DW_AT_HP_unmodifiable, 0x2001) \
	X(DW_AT_HP_prologue, 0x2005) \
	X(DW_AT_HP_epilogue, 0x2008) \
	X(DW_AT_HP_actuals_stmt_list, 0x2010) \
	X(DW_AT_HP_proc_per_section, 0x2011) \
	X(DW_AT_HP_raw_data_ptr, 0x2012) \
	X(DW_AT_HP_pass_by_reference, 0x2013) \
	X(DW_AT_HP_opt_level, 0x2014) \
	X(DW_AT_HP_prof_version_id, 0x2015) \
	X(DW_AT_HP_opt_flags, 0x2016) \
	X(DW_AT_HP_cold_region_low_pc, 0x2017) \
	X(DW_AT_HP_cold_region_high_pc, 0x2018) \
	X(DW_AT_HP_all_variables_modifiable, 0x2019) \
	X(DW_AT_HP_linkage_name, 0x201a) \
	X(DW_AT_HP_prof_flags, 0x201b) \
	X(DW_AT_HP_unit_name, 0x201f) \
	X(DW_AT_HP_unit_size, 0x2020) \
	X(DW_AT_HP_widened_byte_size, 0x2021) \
	X(DW_AT_HP_definition_points, 0x2022) \
	X(DW_AT_HP_default_location, 0x2023) \
	X(DW_AT_HP_is_result_param, 0x2029) \
	X(DW_AT_CPQ_discontig_ranges, 0x2001) \
	X(DW_AT_CPQ_semantic_events, 0x2002) \
	X(DW_AT_CPQ_split_lifetimes_var, 0x2003) \
	X(DW_AT_CPQ_split_lifetimes_rtn, 0x2004) \
	X(DW_AT_CPQ_prologue_length, 0x2005) \
	X(DW_AT_ghs_mangled, 0x2007) \
	X(DW_AT_ghs_rsm, 0x2083) \
	X(DW_AT_ghs_frsm, 0x2085) \
	X(DW_AT_ghs_frames, 0x2086) \
	X(DW_AT_ghs_rso, 0x2087) \
	X(DW_AT_ghs_subcpu, 0x2092) \
	X(DW_AT_ghs_lbrace_line, 0x2093) \
	X(DW_AT_INTEL_other_endian, 0x2026) \
	X(DW_AT_sf_names, 0x2101) \
	X(DW_AT_src_info, 0x2102) \
	X(DW_AT_mac_info, 0x2103) \
	X(DW_AT_src_coords, 0x2104) \
	X(DW_AT_body_begin, 0x2105) \
	X(DW_AT_body_end, 0x2106) \
	X(DW_AT_GNU_vector, 0x2107) \
	X(DW_AT_GNU_guarded_by, 0x2108) \
	X(DW_AT_GNU_pt_guarded_by, 0x2109) \
	X(DW_AT_GNU_guarded, 0x210a) \
	X(DW_AT_GNU_pt_guarded, 0x210b) \
	X(DW_AT_GNU_locks_excluded, 0x210c) \
	X(DW_AT_GNU_exclusive_locks_required, 0x210d) \
	X(DW_AT_GNU_shared_locks_required, 0x210e) \
	X(DW_AT_GNU_odr_signature, 0x210f) \
	X(DW_AT_GNU_template_name, 0x2110) \
	X(DW_AT_GNU_call_site_value, 0x2111) \
	X(DW_AT_GNU_call_site_data_value, 0x2112) \
	X(DW_AT_GNU_call_site_target, 0x2113) \
	X(DW_AT_GNU_call_site_target_clobbered, 0x2114) \
	X(DW_AT_GNU_tail_call, 0x2115) \
	X(DW_AT_GNU_all_tail_call_sites, 0x2116) \
	X(DW_AT_GNU_all_call_sites, 0x2117) \
	X(DW_AT_GNU_all_source_call_sites, 0x2118) \
	X(DW_AT_GNU_macros, 0x2119) \
	X(DW_AT_GNU_deleted, 0x211a) \
	X(DW_AT_GNU_dwo_name, 0x2130) \
	X(DW_AT_GNU_dwo_id, 0x2131) \
	X(DW_AT_GNU_ranges_base, 0x2132) \
	X(DW_AT_GNU_addr_base, 0x2133) \
	X(DW_AT_GNU_pubnames, 0x2134) \
	X(DW_AT_GNU_pubtypes, 0x2135) \
	X(DW_AT_GNU_discriminator, 0x2136) \
	X(DW_AT_GNU_locviews, 0x2137) \
	X(DW_AT_GNU_entry_view, 0x2138) \
	X(DW_AT_GNU_bias, 0x2305) \
	X(DW_AT_SUN_template, 0x2201) \
	X(DW_AT_VMS_rtnbeg_pd_address, 0x2201) \
	X(DW_AT_SUN_alignment, 0x2202) \
	X(DW_AT_SUN_vtable, 0x2203) \
	X(DW_AT_SUN_count_guarantee, 0x2204) \
	X(DW_AT_SUN_command_line, 0x2205) \
	X(DW_AT_SUN_vbase, 0x2206) \
	X(DW_AT_SUN_compile_options, 0x2207) \
	X(DW_AT_SUN_language, 0x2208) \
	X(DW_AT_SUN_browser_file, 0x2209) \
	X(DW_AT_SUN_vtable_abi, 0x2210) \
	X(DW_AT_SUN_func_offsets, 0x2211) \
	X(DW_AT_SUN_cf_kind, 0x2212) \
	X(DW_AT_SUN_vtable_index, 0x2213) \
	X(DW_AT_SUN_omp_tpriv_addr, 0x2214) \
	X(DW_AT_SUN_omp_child_func, 0x2215) \
	X(DW_AT_SUN_func_offset, 0x2216) \
	X(DW_AT_SUN_memop_type_ref, 0x2217) \
	X(DW_AT_SUN_profile_id, 0x2218) \
	X(DW_AT_SUN_memop_signature, 0x2219) \
	X(DW_AT_SUN_obj_dir, 0x2220) \
	X(DW_AT_SUN_obj_file, 0x2221) \
	X(DW_AT_SUN_original_name, 0x2222) \
	X(DW_AT_SUN_hwcprof_signature, 0x2223) \
	X(DW_AT_SUN_amd64_parmdump, 0x2224) \
	X(DW_AT_SUN_part_link_name, 0x2225) \
	X(DW_AT_SUN_link_name, 0x2226) \
	X(DW_AT_SUN_pass_with_const, 0x2227) \
	X(DW_AT_SUN_return_with_const, 0x2228) \
	X(DW_AT_SUN_import_by_name, 0x2229) \
	X(DW_AT_SUN_f90_pointer, 0x222a) \
	X(DW_AT_SUN_pass_by_ref, 0x222b) \
	X(DW_AT_SUN_f90_allocatable, 0x222c) \
	X(DW_AT_SUN_f90_assumed_shape_array, 0x222d) \
	X(DW_AT_SUN_c_vla, 0x222e) \
	X(DW_AT_SUN_return_value_ptr, 0x2230) \
	X(DW_AT_SUN_dtor_start, 0x2231) \
	X(DW_AT_SUN_dtor_length, 0x2232) \
	X(DW_AT_SUN_dtor_state_initial, 0x2233) \
	X(DW_AT_SUN_dtor_state_final, 0x2234) \
	X(DW_AT_SUN_dtor_state_deltas, 0x2235) \
	X(DW_AT_SUN_import_by_lname, 0x2236) \
	X(DW_AT_SUN_f90_use_only, 0x2237) \
	X(DW_AT_SUN_namelist_spec, 0x2238) \
	X(DW_AT_SUN_is_omp_child_func, 0x2239) \
	X(DW_AT_SUN_fortran_main_alias, 0x223a) \
	X(DW_AT_SUN_fortran_based, 0x223b) \
	X(DW_AT_ALTIUM_loclist, 0x2300) \
	X(DW_AT_use_GNAT_descriptive_type, 0x2301) \
	X(DW_AT_GNAT_descriptive_type, 0x2302) \
	X(DW_AT_GNU_numerator, 0x2303) \
	X(DW_AT_GNU_denominator, 0x2304) \
	X(DW_AT_go_kind, 0x2900) \
	X(DW_AT_go_key, 0x2901) \
	X(DW_AT_go_elem, 0x2902) \
	X(DW_AT_go_embedded_field, 0x2903) \
	X(DW_AT_go_runtime_type, 0x2904) \
	X(DW_AT_upc_threads_scaled, 0x3210) \
	X(DW_AT_IBM_wsa_addr, 0x393e) \
	X(DW_AT_IBM_home_location, 0x393f) \
	X(DW_AT_IBM_alt_srcview, 0x3940) \
	X(DW_AT_PGI_lbase, 0x3a00) \
	X(DW_AT_PGI_soffset, 0x3a01) \
	X(DW_AT_PGI_lstride, 0x3a02) \
	X(DW_AT_BORLAND_property_read, 0x3b11) \
	X(DW_AT_BORLAND_property_write, 0x3b12) \
	X(DW_AT_BORLAND_property_implements, 0x3b13) \
	X(DW_AT_BORLAND_property_index, 0x3b14) \
	X(DW_AT_BORLAND_property_default, 0x3b15) \
	X(DW_AT_BORLAND_Delphi_unit, 0x3b20) \
	X(DW_AT_BORLAND_Delphi_class, 0x3b21) \
	X(DW_AT_BORLAND_Delphi_record, 0x3b22) \
	X(DW_AT_BORLAND_Delphi_metaclass, 0x3b23) \
	X(DW_AT_BORLAND_Delphi_constructor, 0x3b24) \
	X(DW_AT_BORLAND_Delphi_destructor, 0x3b25) \
	X(DW_AT_BORLAND_Delphi_anonymous_method, 0x3b26) \
	X(DW_AT_BORLAND_Delphi_interface, 0x3b27) \
	X(DW_AT_BORLAND_Delphi_ABI, 0x3b28) \
	X(DW_AT_BORLAND_Delphi_frameptr, 0x3b30) \
	X(DW_AT_BORLAND_closure, 0x3b31) \
	X(DW_AT_LLVM_include_path, 0x3e00) \
	X(DW_AT_LLVM_config_macros, 0x3e01) \
	X(DW_AT_LLVM_sysroot, 0x3e02) \
	X(DW_AT_LLVM_tag_offset, 0x3e03) \
	X(DW_AT_LLVM_apinotes, 0x3e07) \
	X(DW_AT_LLVM_active_lane, 0x3e08) \
	X(DW_AT_LLVM_augmentation, 0x3e09) \
	X(DW_AT_LLVM_lanes, 0x3e0a) \
	X(DW_AT_LLVM_lane_pc, 0x3e0b) \
	X(DW_AT_LLVM_vector_size, 0x3e0c) \
	X(DW_AT_APPLE_optimized, 0x3fe1) \
	X(DW_AT_APPLE_flags, 0x3fe2) \
	X(DW_AT_APPLE_isa, 0x3fe3) \
	X(DW_AT_APPLE_block, 0x3fe4) \
	X(DW_AT_APPLE_major_runtime_vers, 0x3fe5) \
	X(DW_AT_APPLE_runtime_class, 0x3fe6) \
	X(DW_AT_APPLE_omit_frame_ptr, 0x3fe7) \
	X(DW_AT_APPLE_property_name, 0x3fe8) \
	X(DW_AT_APPLE_property_getter, 0x3fe9) \
	X(DW_AT_APPLE_property_setter, 0x3fea) \
	X(DW_AT_APPLE_property_attribute, 0x3feb) \
	X(DW_AT_APPLE_objc_complete_type, 0x3fec) \
	X(DW_AT_APPLE_property, 0x3fed) \
	X(DW_AT_APPLE_objc_direct, 0x3fee) \
	X(DW_AT_APPLE_sdk, 0x3fef) \
	X(DW_AT_hi_user, 0x3fff)
enum { DW_AT_DEFINITIONS };

#define DW_ATE_DEFINITIONS \
	X(DW_ATE_address, 0x1) \
	X(DW_ATE_boolean, 0x2) \
	X(DW_ATE_complex_float, 0x3) \
	X(DW_ATE_float, 0x4) \
	X(DW_ATE_signed, 0x5) \
	X(DW_ATE_signed_char, 0x6) \
	X(DW_ATE_unsigned, 0x7) \
	X(DW_ATE_unsigned_char, 0x8) \
	X(DW_ATE_imaginary_float, 0x9) \
	X(DW_ATE_packed_decimal, 0xa) \
	X(DW_ATE_numeric_string, 0xb) \
	X(DW_ATE_edited, 0xc) \
	X(DW_ATE_signed_fixed, 0xd) \
	X(DW_ATE_unsigned_fixed, 0xe) \
	X(DW_ATE_decimal_float, 0xf) \
	X(DW_ATE_UTF, 0x10) \
	X(DW_ATE_UCS, 0x11) \
	X(DW_ATE_ASCII, 0x12) \
	X(DW_ATE_ALTIUM_fract, 0x80) \
	X(DW_ATE_lo_user, 0x80) \
	X(DW_ATE_ALTIUM_accum, 0x81) \
	X(DW_ATE_HP_float80, 0x80) \
	X(DW_ATE_HP_complex_float80, 0x81) \
	X(DW_ATE_HP_float128, 0x82) \
	X(DW_ATE_HP_complex_float128, 0x83) \
	X(DW_ATE_HP_floathpintel, 0x84) \
	X(DW_ATE_HP_imaginary_float80, 0x85) \
	X(DW_ATE_HP_imaginary_float128, 0x86) \
	X(DW_ATE_HP_VAX_float, 0x88) \
	X(DW_ATE_HP_VAX_float_d, 0x89) \
	X(DW_ATE_HP_packed_decimal, 0x8a) \
	X(DW_ATE_HP_zoned_decimal, 0x8b) \
	X(DW_ATE_HP_edited, 0x8c) \
	X(DW_ATE_HP_signed_fixed, 0x8d) \
	X(DW_ATE_HP_unsigned_fixed, 0x8e) \
	X(DW_ATE_HP_VAX_complex_float, 0x8f) \
	X(DW_ATE_HP_VAX_complex_float_d, 0x90) \
	X(DW_ATE_SUN_interval_float, 0x91) \
	X(DW_ATE_SUN_imaginary_float, 0x92) \
	X(DW_ATE_hi_user, 0xff)
enum { DW_ATE_DEFINITIONS };

#define DW_CC_DEFINITIONS \
	X(DW_CC_normal, 0x1) \
	X(DW_CC_program, 0x2) \
	X(DW_CC_nocall, 0x3) \
	X(DW_CC_pass_by_reference, 0x4) \
	X(DW_CC_pass_by_value, 0x5) \
	X(DW_CC_lo_user, 0x40) \
	X(DW_CC_GNU_renesas_sh, 0x40) \
	X(DW_CC_GNU_borland_fastcall_i386, 0x41) \
	X(DW_CC_ALTIUM_interrupt, 0x65) \
	X(DW_CC_ALTIUM_near_system_stack, 0x66) \
	X(DW_CC_ALTIUM_near_user_stack, 0x67) \
	X(DW_CC_ALTIUM_huge_user_stack, 0x68) \
	X(DW_CC_GNU_BORLAND_safecall, 0xb0) \
	X(DW_CC_GNU_BORLAND_stdcall, 0xb1) \
	X(DW_CC_GNU_BORLAND_pascal, 0xb2) \
	X(DW_CC_GNU_BORLAND_msfastcall, 0xb3) \
	X(DW_CC_GNU_BORLAND_msreturn, 0xb4) \
	X(DW_CC_GNU_BORLAND_thiscall, 0xb5) \
	X(DW_CC_GNU_BORLAND_fastcall, 0xb6) \
	X(DW_CC_LLVM_vectorcall, 0xc0) \
	X(DW_CC_LLVM_Win64, 0xc1) \
	X(DW_CC_LLVM_X86_64SysV, 0xc2) \
	X(DW_CC_LLVM_AAPCS, 0xc3) \
	X(DW_CC_LLVM_AAPCS_VFP, 0xc4) \
	X(DW_CC_LLVM_IntelOclBicc, 0xc5) \
	X(DW_CC_LLVM_SpirFunction, 0xc6) \
	X(DW_CC_LLVM_OpenCLKernel, 0xc7) \
	X(DW_CC_LLVM_Swift, 0xc8) \
	X(DW_CC_LLVM_PreserveMost, 0xc9) \
	X(DW_CC_LLVM_PreserveAll, 0xca) \
	X(DW_CC_LLVM_X86RegCall, 0xcb) \
	X(DW_CC_GDB_IBM_OpenCL, 0xff) \
	X(DW_CC_hi_user, 0xff)
enum { DW_CC_DEFINITIONS };

#define DW_CFA_DEFINITIONS \
	X(DW_CFA_advance_loc, 0x40) \
	X(DW_CFA_offset, 0x80) \
	X(DW_CFA_restore, 0xc0) \
	X(DW_CFA_nop, 0x0) \
	X(DW_CFA_set_loc, 0x1) \
	X(DW_CFA_advance_loc1, 0x2) \
	X(DW_CFA_advance_loc2, 0x3) \
	X(DW_CFA_advance_loc4, 0x4) \
	X(DW_CFA_offset_extended, 0x5) \
	X(DW_CFA_restore_extended, 0x6) \
	X(DW_CFA_undefined, 0x7) \
	X(DW_CFA_same_value, 0x8) \
	X(DW_CFA_register, 0x9) \
	X(DW_CFA_remember_state, 0xa) \
	X(DW_CFA_restore_state, 0xb) \
	X(DW_CFA_def_cfa, 0xc) \
	X(DW_CFA_def_cfa_register, 0xd) \
	X(DW_CFA_def_cfa_offset, 0xe) \
	X(DW_CFA_def_cfa_expression, 0xf) \
	X(DW_CFA_expression, 0x10) \
	X(DW_CFA_offset_extended_sf, 0x11) \
	X(DW_CFA_def_cfa_sf, 0x12) \
	X(DW_CFA_def_cfa_offset_sf, 0x13) \
	X(DW_CFA_val_offset, 0x14) \
	X(DW_CFA_val_offset_sf, 0x15) \
	X(DW_CFA_val_expression, 0x16) \
	X(DW_CFA_lo_user, 0x1c) \
	X(DW_CFA_MIPS_advance_loc8, 0x1d) \
	X(DW_CFA_GNU_window_save, 0x2d) \
	X(DW_CFA_AARCH64_negate_ra_state, 0x2d) \
	X(DW_CFA_GNU_args_size, 0x2e) \
	X(DW_CFA_GNU_negative_offset_extended, 0x2f) \
	X(DW_CFA_LLVM_def_aspace_cfa, 0x30) \
	X(DW_CFA_LLVM_def_aspace_cfa_sf, 0x31) \
	X(DW_CFA_METAWARE_info, 0x34) \
	X(DW_CFA_hi_user, 0x3f)
enum { DW_CFA_DEFINITIONS };

#define DW_CHILDREN_DEFINITIONS \
	X(DW_CHILDREN_no, 0x0) \
	X(DW_CHILDREN_yes, 0x1)
enum { DW_CHILDREN_DEFINITIONS };

#define DW_DEFAULTED_DEFINITIONS \
	X(DW_DEFAULTED_no, 0x0) \
	X(DW_DEFAULTED_in_class, 0x1) \
	X(DW_DEFAULTED_out_of_class, 0x2)
enum { DW_DEFAULTED_DEFINITIONS };

#define DW_DS_DEFINITIONS \
	X(DW_DS_unsigned, 0x1) \
	X(DW_DS_leading_overpunch, 0x2) \
	X(DW_DS_trailing_overpunch, 0x3) \
	X(DW_DS_leading_separate, 0x4) \
	X(DW_DS_trailing_separate, 0x5)
enum { DW_DS_DEFINITIONS };

#define DW_DSC_DEFINITIONS \
	X(DW_DSC_label, 0x0) \
	X(DW_DSC_range, 0x1)
enum { DW_DSC_DEFINITIONS };

#define DW_EH_PE_DEFINITIONS \
	X(DW_EH_PE_absptr, 0x0) \
	X(DW_EH_PE_uleb128, 0x1) \
	X(DW_EH_PE_udata2, 0x2) \
	X(DW_EH_PE_udata4, 0x3) \
	X(DW_EH_PE_udata8, 0x4) \
	X(DW_EH_PE_sleb128, 0x9) \
	X(DW_EH_PE_sdata2, 0xa) \
	X(DW_EH_PE_sdata4, 0xb) \
	X(DW_EH_PE_sdata8, 0xc) \
	X(DW_EH_PE_signed, 0x8) \
	X(DW_EH_PE_pcrel, 0x10) \
	X(DW_EH_PE_textrel, 0x20) \
	X(DW_EH_PE_datarel, 0x30) \
	X(DW_EH_PE_funcrel, 0x40) \
	X(DW_EH_PE_aligned, 0x50) \
	X(DW_EH_PE_indirect, 0x80) \
	X(DW_EH_PE_omit, 0xff)
enum { DW_EH_PE_DEFINITIONS };

#define DW_END_DEFINITIONS \
	X(DW_END_default, 0x0) \
	X(DW_END_big, 0x1) \
	X(DW_END_little, 0x2) \
	X(DW_END_lo_user, 0x40) \
	X(DW_END_hi_user, 0xff)
enum { DW_END_DEFINITIONS };

#define DW_FORM_DEFINITIONS \
	X(DW_FORM_addr, 0x1) \
	X(DW_FORM_block2, 0x3) \
	X(DW_FORM_block4, 0x4) \
	X(DW_FORM_data2, 0x5) \
	X(DW_FORM_data4, 0x6) \
	X(DW_FORM_data8, 0x7) \
	X(DW_FORM_string, 0x8) \
	X(DW_FORM_block, 0x9) \
	X(DW_FORM_block1, 0xa) \
	X(DW_FORM_data1, 0xb) \
	X(DW_FORM_flag, 0xc) \
	X(DW_FORM_sdata, 0xd) \
	X(DW_FORM_strp, 0xe) \
	X(DW_FORM_udata, 0xf) \
	X(DW_FORM_ref_addr, 0x10) \
	X(DW_FORM_ref1, 0x11) \
	X(DW_FORM_ref2, 0x12) \
	X(DW_FORM_ref4, 0x13) \
	X(DW_FORM_ref8, 0x14) \
	X(DW_FORM_ref_udata, 0x15) \
	X(DW_FORM_indirect, 0x16) \
	X(DW_FORM_sec_offset, 0x17) \
	X(DW_FORM_exprloc, 0x18) \
	X(DW_FORM_flag_present, 0x19) \
	X(DW_FORM_strx, 0x1a) \
	X(DW_FORM_addrx, 0x1b) \
	X(DW_FORM_ref_sup4, 0x1c) \
	X(DW_FORM_strp_sup, 0x1d) \
	X(DW_FORM_data16, 0x1e) \
	X(DW_FORM_line_strp, 0x1f) \
	X(DW_FORM_ref_sig8, 0x20) \
	X(DW_FORM_implicit_const, 0x21) \
	X(DW_FORM_loclistx, 0x22) \
	X(DW_FORM_rnglistx, 0x23) \
	X(DW_FORM_ref_sup8, 0x24) \
	X(DW_FORM_strx1, 0x25) \
	X(DW_FORM_strx2, 0x26) \
	X(DW_FORM_strx3, 0x27) \
	X(DW_FORM_strx4, 0x28) \
	X(DW_FORM_addrx1, 0x29) \
	X(DW_FORM_addrx2, 0x2a) \
	X(DW_FORM_addrx3, 0x2b) \
	X(DW_FORM_addrx4, 0x2c) \
	X(DW_FORM_GNU_addr_index, 0x1f01) \
	X(DW_FORM_GNU_str_index, 0x1f02) \
	X(DW_FORM_GNU_ref_alt, 0x1f20) \
	X(DW_FORM_GNU_strp_alt, 0x1f21) \
	X(DW_FORM_LLVM_addrx_offset, 0x2001)
enum { DW_FORM_DEFINITIONS };

#define DW_ID_DEFINITIONS \
	X(DW_ID_case_sensitive, 0x0) \
	X(DW_ID_up_case, 0x1) \
	X(DW_ID_down_case, 0x2) \
	X(DW_ID_case_insensitive, 0x3)
enum { DW_ID_DEFINITIONS };

#define DW_IDX_DEFINITIONS \
	X(DW_IDX_compile_unit, 0x1) \
	X(DW_IDX_type_unit, 0x2) \
	X(DW_IDX_die_offset, 0x3) \
	X(DW_IDX_parent, 0x4) \
	X(DW_IDX_type_hash, 0x5) \
	X(DW_IDX_GNU_internal, 0x2000) \
	X(DW_IDX_lo_user, 0x2000) \
	X(DW_IDX_GNU_external, 0x2001) \
	X(DW_IDX_hi_user, 0x3fff)
enum { DW_IDX_DEFINITIONS };

#define DW_INL_DEFINITIONS \
	X(DW_INL_not_inlined, 0x0) \
	X(DW_INL_inlined, 0x1) \
	X(DW_INL_declared_not_inlined, 0x2) \
	X(DW_INL_declared_inlined, 0x3)
enum { DW_INL_DEFINITIONS };

#define DW_LANG_DEFINITIONS \
	X(DW_LANG_C89, 0x1) \
	X(DW_LANG_C, 0x2) \
	X(DW_LANG_Ada83, 0x3) \
	X(DW_LANG_C_plus_plus, 0x4) \
	X(DW_LANG_Cobol74, 0x5) \
	X(DW_LANG_Cobol85, 0x6) \
	X(DW_LANG_Fortran77, 0x7) \
	X(DW_LANG_Fortran90, 0x8) \
	X(DW_LANG_Pascal83, 0x9) \
	X(DW_LANG_Modula2, 0xa) \
	X(DW_LANG_Java, 0xb) \
	X(DW_LANG_C99, 0xc) \
	X(DW_LANG_Ada95, 0xd) \
	X(DW_LANG_Fortran95, 0xe) \
	X(DW_LANG_PLI, 0xf) \
	X(DW_LANG_ObjC, 0x10) \
	X(DW_LANG_ObjC_plus_plus, 0x11) \
	X(DW_LANG_UPC, 0x12) \
	X(DW_LANG_D, 0x13) \
	X(DW_LANG_Python, 0x14) \
	X(DW_LANG_OpenCL, 0x15) \
	X(DW_LANG_Go, 0x16) \
	X(DW_LANG_Modula3, 0x17) \
	X(DW_LANG_Haskell, 0x18) \
	X(DW_LANG_C_plus_plus_03, 0x19) \
	X(DW_LANG_C_plus_plus_11, 0x1a) \
	X(DW_LANG_OCaml, 0x1b) \
	X(DW_LANG_Rust, 0x1c) \
	X(DW_LANG_C11, 0x1d) \
	X(DW_LANG_Swift, 0x1e) \
	X(DW_LANG_Julia, 0x1f) \
	X(DW_LANG_Dylan, 0x20) \
	X(DW_LANG_C_plus_plus_14, 0x21) \
	X(DW_LANG_Fortran03, 0x22) \
	X(DW_LANG_Fortran08, 0x23) \
	X(DW_LANG_RenderScript, 0x24) \
	X(DW_LANG_BLISS, 0x25) \
	X(DW_LANG_lo_user, 0x8000) \
	X(DW_LANG_Mips_Assembler, 0x8001) \
	X(DW_LANG_Upc, 0x8765) \
	X(DW_LANG_GOOGLE_RenderScript, 0x8001) \
	X(DW_LANG_ALTIUM_Assembler, 0x9101) \
	X(DW_LANG_BORLAND_Delphi, 0xb000) \
	X(DW_LANG_SUN_Assembler, 0x9001) \
	X(DW_LANG_hi_user, 0xffff)
enum { DW_LANG_DEFINITIONS };

#define DW_LLE_DEFINITIONS \
	X(DW_LLE_end_of_list, 0x0) \
	X(DW_LLE_base_addressx, 0x1) \
	X(DW_LLE_startx_endx, 0x2) \
	X(DW_LLE_startx_length, 0x3) \
	X(DW_LLE_offset_pair, 0x4) \
	X(DW_LLE_default_location, 0x5) \
	X(DW_LLE_base_address, 0x6) \
	X(DW_LLE_start_end, 0x7) \
	X(DW_LLE_start_length, 0x8)
enum { DW_LLE_DEFINITIONS };

#define DW_LNCT_DEFINITIONS \
	X(DW_LNCT_path, 0x1) \
	X(DW_LNCT_directory_index, 0x2) \
	X(DW_LNCT_timestamp, 0x3) \
	X(DW_LNCT_size, 0x4) \
	X(DW_LNCT_MD5, 0x5) \
	X(DW_LNCT_GNU_subprogram_name, 0x6) \
	X(DW_LNCT_GNU_decl_file, 0x7) \
	X(DW_LNCT_GNU_decl_line, 0x8) \
	X(DW_LNCT_lo_user, 0x2000) \
	X(DW_LNCT_LLVM_source, 0x2001) \
	X(DW_LNCT_LLVM_is_MD5, 0x2002) \
	X(DW_LNCT_hi_user, 0x3fff)
enum { DW_LNCT_DEFINITIONS };

#define DW_LNE_DEFINITIONS \
	X(DW_LNE_end_sequence, 0x1) \
	X(DW_LNE_set_address, 0x2) \
	X(DW_LNE_define_file, 0x3) \
	X(DW_LNE_set_discriminator, 0x4) \
	X(DW_LNE_HP_negate_is_UV_update, 0x11) \
	X(DW_LNE_HP_push_context, 0x12) \
	X(DW_LNE_HP_pop_context, 0x13) \
	X(DW_LNE_HP_set_file_line_column, 0x14) \
	X(DW_LNE_HP_set_routine_name, 0x15) \
	X(DW_LNE_HP_set_sequence, 0x16) \
	X(DW_LNE_HP_negate_post_semantics, 0x17) \
	X(DW_LNE_HP_negate_function_exit, 0x18) \
	X(DW_LNE_HP_negate_front_end_logical, 0x19) \
	X(DW_LNE_HP_define_proc, 0x20) \
	X(DW_LNE_HP_source_file_correlation, 0x80) \
	X(DW_LNE_lo_user, 0x80) \
	X(DW_LNE_hi_user, 0xff)
enum { DW_LNE_DEFINITIONS };

#define DW_LNS_DEFINITIONS \
	X(DW_LNS_copy, 0x1) \
	X(DW_LNS_advance_pc, 0x2) \
	X(DW_LNS_advance_line, 0x3) \
	X(DW_LNS_set_file, 0x4) \
	X(DW_LNS_set_column, 0x5) \
	X(DW_LNS_negate_stmt, 0x6) \
	X(DW_LNS_set_basic_block, 0x7) \
	X(DW_LNS_const_add_pc, 0x8) \
	X(DW_LNS_fixed_advance_pc, 0x9) \
	X(DW_LNS_set_prologue_end, 0xa) \
	X(DW_LNS_set_epilogue_begin, 0xb) \
	X(DW_LNS_set_isa, 0xc) \
	X(DW_LNS_set_address_from_logical, 0xd) \
	X(DW_LNS_set_subprogram, 0xd) \
	X(DW_LNS_inlined_call, 0xe) \
	X(DW_LNS_pop_context, 0xf)
enum { DW_LNS_DEFINITIONS };

#define DW_MACINFO_DEFINITIONS \
	X(DW_MACINFO_define, 0x1) \
	X(DW_MACINFO_undef, 0x2) \
	X(DW_MACINFO_start_file, 0x3) \
	X(DW_MACINFO_end_file, 0x4) \
	X(DW_MACINFO_vendor_ext, 0xff)
enum { DW_MACINFO_DEFINITIONS };

#define DW_MACRO_DEFINITIONS \
	X(DW_MACRO_define, 0x1) \
	X(DW_MACRO_undef, 0x2) \
	X(DW_MACRO_start_file, 0x3) \
	X(DW_MACRO_end_file, 0x4) \
	X(DW_MACRO_define_strp, 0x5) \
	X(DW_MACRO_undef_strp, 0x6) \
	X(DW_MACRO_import, 0x7) \
	X(DW_MACRO_define_sup, 0x8) \
	X(DW_MACRO_undef_sup, 0x9) \
	X(DW_MACRO_import_sup, 0xa) \
	X(DW_MACRO_define_strx, 0xb) \
	X(DW_MACRO_undef_strx, 0xc) \
	X(DW_MACRO_lo_user, 0xe0) \
	X(DW_MACRO_hi_user, 0xff)
enum { DW_MACRO_DEFINITIONS };

#define DW_OP_DEFINITIONS \
	X(DW_OP_addr, 0x3) \
	X(DW_OP_deref, 0x6) \
	X(DW_OP_const1u, 0x8) \
	X(DW_OP_const1s, 0x9) \
	X(DW_OP_const2u, 0xa) \
	X(DW_OP_const2s, 0xb) \
	X(DW_OP_const4u, 0xc) \
	X(DW_OP_const4s, 0xd) \
	X(DW_OP_const8u, 0xe) \
	X(DW_OP_const8s, 0xf) \
	X(DW_OP_constu, 0x10) \
	X(DW_OP_consts, 0x11) \
	X(DW_OP_dup, 0x12) \
	X(DW_OP_drop, 0x13) \
	X(DW_OP_over, 0x14) \
	X(DW_OP_pick, 0x15) \
	X(DW_OP_swap, 0x16) \
	X(DW_OP_rot, 0x17) \
	X(DW_OP_xderef, 0x18) \
	X(DW_OP_abs, 0x19) \
	X(DW_OP_and, 0x1a) \
	X(DW_OP_div, 0x1b) \
	X(DW_OP_minus, 0x1c) \
	X(DW_OP_mod, 0x1d) \
	X(DW_OP_mul, 0x1e) \
	X(DW_OP_neg, 0x1f) \
	X(DW_OP_not, 0x20) \
	X(DW_OP_or, 0x21) \
	X(DW_OP_plus, 0x22) \
	X(DW_OP_plus_uconst, 0x23) \
	X(DW_OP_shl, 0x24) \
	X(DW_OP_shr, 0x25) \
	X(DW_OP_shra, 0x26) \
	X(DW_OP_xor, 0x27) \
	X(DW_OP_bra, 0x28) \
	X(DW_OP_eq, 0x29) \
	X(DW_OP_ge, 0x2a) \
	X(DW_OP_gt, 0x2b) \
	X(DW_OP_le, 0x2c) \
	X(DW_OP_lt, 0x2d) \
	X(DW_OP_ne, 0x2e) \
	X(DW_OP_skip, 0x2f) \
	X(DW_OP_lit0, 0x30) \
	X(DW_OP_lit1, 0x31) \
	X(DW_OP_lit2, 0x32) \
	X(DW_OP_lit3, 0x33) \
	X(DW_OP_lit4, 0x34) \
	X(DW_OP_lit5, 0x35) \
	X(DW_OP_lit6, 0x36) \
	X(DW_OP_lit7, 0x37) \
	X(DW_OP_lit8, 0x38) \
	X(DW_OP_lit9, 0x39) \
	X(DW_OP_lit10, 0x3a) \
	X(DW_OP_lit11, 0x3b) \
	X(DW_OP_lit12, 0x3c) \
	X(DW_OP_lit13, 0x3d) \
	X(DW_OP_lit14, 0x3e) \
	X(DW_OP_lit15, 0x3f) \
	X(DW_OP_lit16, 0x40) \
	X(DW_OP_lit17, 0x41) \
	X(DW_OP_lit18, 0x42) \
	X(DW_OP_lit19, 0x43) \
	X(DW_OP_lit20, 0x44) \
	X(DW_OP_lit21, 0x45) \
	X(DW_OP_lit22, 0x46) \
	X(DW_OP_lit23, 0x47) \
	X(DW_OP_lit24, 0x48) \
	X(DW_OP_lit25, 0x49) \
	X(DW_OP_lit26, 0x4a) \
	X(DW_OP_lit27, 0x4b) \
	X(DW_OP_lit28, 0x4c) \
	X(DW_OP_lit29, 0x4d) \
	X(DW_OP_lit30, 0x4e) \
	X(DW_OP_lit31, 0x4f) \
	X(DW_OP_reg0, 0x50) \
	X(DW_OP_reg1, 0x51) \
	X(DW_OP_reg2, 0x52) \
	X(DW_OP_reg3, 0x53) \
	X(DW_OP_reg4, 0x54) \
	X(DW_OP_reg5, 0x55) \
	X(DW_OP_reg6, 0x56) \
	X(DW_OP_reg7, 0x57) \
	X(DW_OP_reg8, 0x58) \
	X(DW_OP_reg9, 0x59) \
	X(DW_OP_reg10, 0x5a) \
	X(DW_OP_reg11, 0x5b) \
	X(DW_OP_reg12, 0x5c) \
	X(DW_OP_reg13, 0x5d) \
	X(DW_OP_reg14, 0x5e) \
	X(DW_OP_reg15, 0x5f) \
	X(DW_OP_reg16, 0x60) \
	X(DW_OP_reg17, 0x61) \
	X(DW_OP_reg18, 0x62) \
	X(DW_OP_reg19, 0x63) \
	X(DW_OP_reg20, 0x64) \
	X(DW_OP_reg21, 0x65) \
	X(DW_OP_reg22, 0x66) \
	X(DW_OP_reg23, 0x67) \
	X(DW_OP_reg24, 0x68) \
	X(DW_OP_reg25, 0x69) \
	X(DW_OP_reg26, 0x6a) \
	X(DW_OP_reg27, 0x6b) \
	X(DW_OP_reg28, 0x6c) \
	X(DW_OP_reg29, 0x6d) \
	X(DW_OP_reg30, 0x6e) \
	X(DW_OP_reg31, 0x6f) \
	X(DW_OP_breg0, 0x70) \
	X(DW_OP_breg1, 0x71) \
	X(DW_OP_breg2, 0x72) \
	X(DW_OP_breg3, 0x73) \
	X(DW_OP_breg4, 0x74) \
	X(DW_OP_breg5, 0x75) \
	X(DW_OP_breg6, 0x76) \
	X(DW_OP_breg7, 0x77) \
	X(DW_OP_breg8, 0x78) \
	X(DW_OP_breg9, 0x79) \
	X(DW_OP_breg10, 0x7a) \
	X(DW_OP_breg11, 0x7b) \
	X(DW_OP_breg12, 0x7c) \
	X(DW_OP_breg13, 0x7d) \
	X(DW_OP_breg14, 0x7e) \
	X(DW_OP_breg15, 0x7f) \
	X(DW_OP_breg16, 0x80) \
	X(DW_OP_breg17, 0x81) \
	X(DW_OP_breg18, 0x82) \
	X(DW_OP_breg19, 0x83) \
	X(DW_OP_breg20, 0x84) \
	X(DW_OP_breg21, 0x85) \
	X(DW_OP_breg22, 0x86) \
	X(DW_OP_breg23, 0x87) \
	X(DW_OP_breg24, 0x88) \
	X(DW_OP_breg25, 0x89) \
	X(DW_OP_breg26, 0x8a) \
	X(DW_OP_breg27, 0x8b) \
	X(DW_OP_breg28, 0x8c) \
	X(DW_OP_breg29, 0x8d) \
	X(DW_OP_breg30, 0x8e) \
	X(DW_OP_breg31, 0x8f) \
	X(DW_OP_regx, 0x90) \
	X(DW_OP_fbreg, 0x91) \
	X(DW_OP_bregx, 0x92) \
	X(DW_OP_piece, 0x93) \
	X(DW_OP_deref_size, 0x94) \
	X(DW_OP_xderef_size, 0x95) \
	X(DW_OP_nop, 0x96) \
	X(DW_OP_push_object_address, 0x97) \
	X(DW_OP_call2, 0x98) \
	X(DW_OP_call4, 0x99) \
	X(DW_OP_call_ref, 0x9a) \
	X(DW_OP_form_tls_address, 0x9b) \
	X(DW_OP_call_frame_cfa, 0x9c) \
	X(DW_OP_bit_piece, 0x9d) \
	X(DW_OP_implicit_value, 0x9e) \
	X(DW_OP_stack_value, 0x9f) \
	X(DW_OP_implicit_pointer, 0xa0) \
	X(DW_OP_addrx, 0xa1) \
	X(DW_OP_constx, 0xa2) \
	X(DW_OP_entry_value, 0xa3) \
	X(DW_OP_const_type, 0xa4) \
	X(DW_OP_regval_type, 0xa5) \
	X(DW_OP_deref_type, 0xa6) \
	X(DW_OP_xderef_type, 0xa7) \
	X(DW_OP_convert, 0xa8) \
	X(DW_OP_reinterpret, 0xa9) \
	X(DW_OP_GNU_push_tls_address, 0xe0) \
	X(DW_OP_WASM_location, 0xed) \
	X(DW_OP_WASM_location_int, 0xee) \
	X(DW_OP_lo_user, 0xe0) \
	X(DW_OP_LLVM_form_aspace_address, 0xe1) \
	X(DW_OP_LLVM_push_lane, 0xe2) \
	X(DW_OP_LLVM_offset, 0xe3) \
	X(DW_OP_LLVM_offset_uconst, 0xe4) \
	X(DW_OP_LLVM_bit_offset, 0xe5) \
	X(DW_OP_LLVM_call_frame_entry_reg, 0xe6) \
	X(DW_OP_LLVM_undefined, 0xe7) \
	X(DW_OP_LLVM_aspace_bregx, 0xe8) \
	X(DW_OP_LLVM_aspace_implicit_pointer, 0xe9) \
	X(DW_OP_LLVM_piece_end, 0xea) \
	X(DW_OP_LLVM_extend, 0xeb) \
	X(DW_OP_LLVM_select_bit_piece, 0xec) \
	X(DW_OP_HP_unknown, 0xe0) \
	X(DW_OP_HP_is_value, 0xe1) \
	X(DW_OP_HP_fltconst4, 0xe2) \
	X(DW_OP_HP_fltconst8, 0xe3) \
	X(DW_OP_HP_mod_range, 0xe4) \
	X(DW_OP_HP_unmod_range, 0xe5) \
	X(DW_OP_HP_tls, 0xe6) \
	X(DW_OP_INTEL_bit_piece, 0xe8) \
	X(DW_OP_GNU_uninit, 0xf0) \
	X(DW_OP_APPLE_uninit, 0xf0) \
	X(DW_OP_GNU_encoded_addr, 0xf1) \
	X(DW_OP_GNU_implicit_pointer, 0xf2) \
	X(DW_OP_GNU_entry_value, 0xf3) \
	X(DW_OP_GNU_const_type, 0xf4) \
	X(DW_OP_GNU_regval_type, 0xf5) \
	X(DW_OP_GNU_deref_type, 0xf6) \
	X(DW_OP_GNU_convert, 0xf7) \
	X(DW_OP_GNU_reinterpret, 0xf9) \
	X(DW_OP_GNU_parameter_ref, 0xfa) \
	X(DW_OP_GNU_addr_index, 0xfb) \
	X(DW_OP_GNU_const_index, 0xfc) \
	X(DW_OP_GNU_variable_value, 0xfd) \
	X(DW_OP_PGI_omp_thread_num, 0xf8) \
	X(DW_OP_hi_user, 0xff)
enum { DW_OP_DEFINITIONS };

#define DW_ORD_DEFINITIONS \
	X(DW_ORD_row_major, 0x0) \
	X(DW_ORD_col_major, 0x1)
enum { DW_ORD_DEFINITIONS };

#define DW_RLE_DEFINITIONS \
	X(DW_RLE_end_of_list, 0x0) \
	X(DW_RLE_base_addressx, 0x1) \
	X(DW_RLE_startx_endx, 0x2) \
	X(DW_RLE_startx_length, 0x3) \
	X(DW_RLE_offset_pair, 0x4) \
	X(DW_RLE_base_address, 0x5) \
	X(DW_RLE_start_end, 0x6) \
	X(DW_RLE_start_length, 0x7)
enum { DW_RLE_DEFINITIONS };

#define DW_SECT_DEFINITIONS \
	X(DW_SECT_INFO, 0x1) \
	X(DW_SECT_TYPES, 0x2) \
	X(DW_SECT_ABBREV, 0x3) \
	X(DW_SECT_LINE, 0x4) \
	X(DW_SECT_LOCLISTS, 0x5) \
	X(DW_SECT_STR_OFFSETS, 0x6) \
	X(DW_SECT_MACRO, 0x7) \
	X(DW_SECT_RNGLISTS, 0x8)
enum { DW_SECT_DEFINITIONS };

#define DW_TAG_DEFINITIONS \
	X(DW_TAG_array_type, 0x1) \
	X(DW_TAG_class_type, 0x2) \
	X(DW_TAG_entry_point, 0x3) \
	X(DW_TAG_enumeration_type, 0x4) \
	X(DW_TAG_formal_parameter, 0x5) \
	X(DW_TAG_imported_declaration, 0x8) \
	X(DW_TAG_label, 0xa) \
	X(DW_TAG_lexical_block, 0xb) \
	X(DW_TAG_member, 0xd) \
	X(DW_TAG_pointer_type, 0xf) \
	X(DW_TAG_reference_type, 0x10) \
	X(DW_TAG_compile_unit, 0x11) \
	X(DW_TAG_string_type, 0x12) \
	X(DW_TAG_structure_type, 0x13) \
	X(DW_TAG_subroutine_type, 0x15) \
	X(DW_TAG_typedef, 0x16) \
	X(DW_TAG_union_type, 0x17) \
	X(DW_TAG_unspecified_parameters, 0x18) \
	X(DW_TAG_variant, 0x19) \
	X(DW_TAG_common_block, 0x1a) \
	X(DW_TAG_common_inclusion, 0x1b) \
	X(DW_TAG_inheritance, 0x1c) \
	X(DW_TAG_inlined_subroutine, 0x1d) \
	X(DW_TAG_module, 0x1e) \
	X(DW_TAG_ptr_to_member_type, 0x1f) \
	X(DW_TAG_set_type, 0x20) \
	X(DW_TAG_subrange_type, 0x21) \
	X(DW_TAG_with_stmt, 0x22) \
	X(DW_TAG_access_declaration, 0x23) \
	X(DW_TAG_base_type, 0x24) \
	X(DW_TAG_catch_block, 0x25) \
	X(DW_TAG_const_type, 0x26) \
	X(DW_TAG_constant, 0x27) \
	X(DW_TAG_enumerator, 0x28) \
	X(DW_TAG_file_type, 0x29) \
	X(DW_TAG_friend, 0x2a) \
	X(DW_TAG_namelist, 0x2b) \
	X(DW_TAG_namelist_item, 0x2c) \
	X(DW_TAG_packed_type, 0x2d) \
	X(DW_TAG_subprogram, 0x2e) \
	X(DW_TAG_template_type_parameter, 0x2f) \
	X(DW_TAG_template_value_parameter, 0x30) \
	X(DW_TAG_thrown_type, 0x31) \
	X(DW_TAG_try_block, 0x32) \
	X(DW_TAG_variant_part, 0x33) \
	X(DW_TAG_variable, 0x34) \
	X(DW_TAG_volatile_type, 0x35) \
	X(DW_TAG_dwarf_procedure, 0x36) \
	X(DW_TAG_restrict_type, 0x37) \
	X(DW_TAG_interface_type, 0x38) \
	X(DW_TAG_namespace, 0x39) \
	X(DW_TAG_imported_module, 0x3a) \
	X(DW_TAG_unspecified_type, 0x3b) \
	X(DW_TAG_partial_unit, 0x3c) \
	X(DW_TAG_imported_unit, 0x3d) \
	X(DW_TAG_mutable_type, 0x3e) \
	X(DW_TAG_condition, 0x3f) \
	X(DW_TAG_shared_type, 0x40) \
	X(DW_TAG_type_unit, 0x41) \
	X(DW_TAG_rvalue_reference_type, 0x42) \
	X(DW_TAG_template_alias, 0x43) \
	X(DW_TAG_coarray_type, 0x44) \
	X(DW_TAG_generic_subrange, 0x45) \
	X(DW_TAG_dynamic_type, 0x46) \
	X(DW_TAG_atomic_type, 0x47) \
	X(DW_TAG_call_site, 0x48) \
	X(DW_TAG_call_site_parameter, 0x49) \
	X(DW_TAG_skeleton_unit, 0x4a) \
	X(DW_TAG_immutable_type, 0x4b) \
	X(DW_TAG_lo_user, 0x4080) \
	X(DW_TAG_MIPS_loop, 0x4081) \
	X(DW_TAG_HP_array_descriptor, 0x4090) \
	X(DW_TAG_format_label, 0x4101) \
	X(DW_TAG_function_template, 0x4102) \
	X(DW_TAG_class_template, 0x4103) \
	X(DW_TAG_GNU_BINCL, 0x4104) \
	X(DW_TAG_GNU_EINCL, 0x4105) \
	X(DW_TAG_GNU_template_template_param, 0x4106) \
	X(DW_TAG_GNU_template_parameter_pack, 0x4107) \
	X(DW_TAG_GNU_formal_parameter_pack, 0x4108) \
	X(DW_TAG_GNU_call_site, 0x4109) \
	X(DW_TAG_GNU_call_site_parameter, 0x410a) \
	X(DW_TAG_SUN_function_template, 0x4201) \
	X(DW_TAG_SUN_class_template, 0x4202) \
	X(DW_TAG_SUN_struct_template, 0x4203) \
	X(DW_TAG_SUN_union_template, 0x4204) \
	X(DW_TAG_SUN_indirect_inheritance, 0x4205) \
	X(DW_TAG_SUN_codeflags, 0x4206) \
	X(DW_TAG_SUN_memop_info, 0x4207) \
	X(DW_TAG_SUN_omp_child_func, 0x4208) \
	X(DW_TAG_SUN_rtti_descriptor, 0x4209) \
	X(DW_TAG_SUN_dtor_info, 0x420a) \
	X(DW_TAG_SUN_dtor, 0x420b) \
	X(DW_TAG_SUN_f90_interface, 0x420c) \
	X(DW_TAG_SUN_fortran_vax_structure, 0x420d) \
	X(DW_TAG_SUN_hi, 0x42ff) \
	X(DW_TAG_ALTIUM_circ_type, 0x5101) \
	X(DW_TAG_ALTIUM_mwa_circ_type, 0x5102) \
	X(DW_TAG_ALTIUM_rev_carry_type, 0x5103) \
	X(DW_TAG_ALTIUM_rom, 0x5111) \
	X(DW_TAG_LLVM_annotation, 0x6000) \
	X(DW_TAG_ghs_namespace, 0x8004) \
	X(DW_TAG_ghs_using_namespace, 0x8005) \
	X(DW_TAG_ghs_using_declaration, 0x8006) \
	X(DW_TAG_ghs_template_templ_param, 0x8007) \
	X(DW_TAG_upc_shared_type, 0x8765) \
	X(DW_TAG_upc_strict_type, 0x8766) \
	X(DW_TAG_upc_relaxed_type, 0x8767) \
	X(DW_TAG_PGI_kanji_type, 0xa000) \
	X(DW_TAG_PGI_interface_block, 0xa020) \
	X(DW_TAG_BORLAND_property, 0xb000) \
	X(DW_TAG_BORLAND_Delphi_string, 0xb001) \
	X(DW_TAG_BORLAND_Delphi_dynamic_array, 0xb002) \
	X(DW_TAG_BORLAND_Delphi_set, 0xb003) \
	X(DW_TAG_BORLAND_Delphi_variant, 0xb004) \
	X(DW_TAG_hi_user, 0xffff)
enum { DW_TAG_DEFINITIONS };
#define DW_TAG_STR_UNKNOWN_FORMAT "DW_TAG_<0x%x>"
#define DW_TAG_STR_BUF_LEN (sizeof(DW_TAG_STR_UNKNOWN_FORMAT) - 2 + 2 * sizeof(int))
/**
 * Get the name of a `DW_TAG` value.
 *
 * @return Static string if the value is known or @p buf if the value is
 * unknown.
 */
const char *dw_tag_str(int value, char buf[static DW_TAG_STR_BUF_LEN]);

#define DW_UT_DEFINITIONS \
	X(DW_UT_compile, 0x1) \
	X(DW_UT_type, 0x2) \
	X(DW_UT_partial, 0x3) \
	X(DW_UT_skeleton, 0x4) \
	X(DW_UT_split_compile, 0x5) \
	X(DW_UT_split_type, 0x6) \
	X(DW_UT_lo_user, 0x80) \
	X(DW_UT_hi_user, 0xff)
enum { DW_UT_DEFINITIONS };

#define DW_VIRTUALITY_DEFINITIONS \
	X(DW_VIRTUALITY_none, 0x0) \
	X(DW_VIRTUALITY_virtual, 0x1) \
	X(DW_VIRTUALITY_pure_virtual, 0x2)
enum { DW_VIRTUALITY_DEFINITIONS };

#define DW_VIS_DEFINITIONS \
	X(DW_VIS_local, 0x1) \
	X(DW_VIS_exported, 0x2) \
	X(DW_VIS_qualified, 0x3)
enum { DW_VIS_DEFINITIONS };

#undef X

#endif /* DWARF_CONSTANTS_H */
