/*
 * elf_policy_linux.c
 *
 *  Created on: Feb 27, 2012
 *      Author: julian
 */

struct kmem_cache *elfp_slab_region, *elfp_slab_policy, *elfp_slab_call_transition, *elfp_slab_data_transition;

void __init elfp_init(void) {
	elfp_slab_region =  kmem_cache_create("elf_policy_region",
			sizeof(struct elf_policy_region), 0, 0, NULL);
	elfp_slab_policy = kmem_cache_create("elfp_policy",
			sizeof(struct elf_policy), 0, 0, NULL);
	elfp_slab_call_transition =  kmem_cache_create("elfp_policy_call_transition",
			sizeof(struct elf_policy_call_transition), 0, 0, NULL);
	elfp_slab_data_transition =  kmem_cache_create("elfp_policy_data_transition",
			sizeof(struct elf_policy_data_transition), 0, 0, NULL);
}
