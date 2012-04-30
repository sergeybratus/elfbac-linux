/* elfp.c
 * System calls to modify ELF policy
 * (c) 2011-2012 Julian Bangert
 * Released under the GPLv2/BSD dual license (except for the functions marked as such, which are just GPLv2)
 */
#include "elf_policy_linux.c"
int elfp_handle_instruction_address_fault(uintptr_t address,
		elfp_process_t *tsk) {
	struct elfp_state *state = elfp_task_get_current_state(tsk);
	if (!elfp_address_in_segment(address,state)) {
		struct elfp_call_transition *transition = state->calls;
		while(transition && (transition->offset != address)){
			if(transition->offset < address)
				transition = transition->left;
			else
				transition = transition->right;
		}
		if(unlikely(!transition)){
			return 0; /* Kill process */
		}
		else{
			elfp_os_change_context(tsk,transition->to);/* TODO: Copy stack, handle return */
			return 1;
		}
	}
	return 0; /* Fail */
}
int elfp_handle_data_address_fault(uintptr_t address, elfp_process_t *tsk,int access_type){
	struct elfp_state *state = elfp_task_get_current_state(tsk);
	struct elfp_data_transition *transition = state->data;
	while(transition && (transition->high < address || transition->low >address)){
		if(address < transition->low)
			transition = transition->left;
		else /* address > transition->high */
			transition = transition->right;
	}
	if(transition){
		if(state == transition->to){
			elfp_os_copy_mapping(tsk,state->context, transition->low, transition->high);
			return 1;
		}
		else{
			elfp_os_change_context(tsk,transition->to);
			return 1;
		}
	}
	else
		return 0; /* Kill process ? */
	return 0;
}
/* code for parsing policies*/
inline int elfp_read_safe(uintptr_t start,uintptr_t end, uintptr_t offset, size_t s,void *buf,elfp_process_t *tsk){
	unsigned long tmp;
	if(offset< start)
		return 0;
	if(offset+s > end)
		return 0;
	while(s){
		tmp = elfp_read_policy(offset,buf,s,tsk);
		if(!tmp) return -1;
		s -= tmp;
		offset += tmp;
		buf += tmp;
	}
	return 0;
}
static int elfp_insert_data_transition(struct elfp_data_transition *data){
	struct elfp_data_transition ** tree = &(data->from->data);
	while (*tree) {
		if ((*tree)->to > data->to)
			tree = &((*tree)->left);
		else if ((*tree)->to < data->to)
			tree = &((*tree)->right);
		else {/* We do not need to sort on high, but TODO: make sure they don't overlap */
			if ((*tree)->low < data->low)
				tree = &((*tree)->left);
			else {
				tree = &((*tree)->right);
			}
		}
	}
	*tree = data;
	data->left = data->right =NULL;
	return 0;
}
static int elfp_insert_call_transition(struct elfp_call_transition *data){
	struct elfp_call_transition **tree = &(data->from->calls);
	while(*tree){
		if ((*tree)->to > data->to)
				tree = &((*tree)->left);
		else if((*tree)->to < data->to)
				tree =  &((*tree)->right);
		else {/* We do not need to sort on high, but TODO: make sure they don't overlap */
			if((*tree)->offset < data->offset)
				tree = &((*tree)->left);
			else {
				tree =  &((*tree)->right);
			}
		}
	}
	*tree = data;
	data->left = data->right = NULL;
	return 0;
}
static struct elfp_state *elfp_find_state_by_id(struct elf_policy * pol, elfp_id_t id){
	struct elfp_state *retval = pol->states;
	while(retval && id!=retval->id)
		retval = retval->next;
	if(retval)
		return retval;
	else
		return NULL;
}
int elfp_parse_policy(uintptr_t start,uintptr_t end, elfp_process_t *tsk){
	struct elf_policy *pol;
	struct elfp_desc_header hdr;
	uintptr_t off = start;
	if(elfp_read_safe(start,end,off,sizeof hdr,&hdr,tsk))
		return -EIO;
	off+= sizeof hdr;
	pol = elfp_alloc_policy();
	if(!pol)
		return -ENOMEM;
	pol->states = NULL;
	elfp_os_atomic_init(&pol->refs,0);
	while(hdr.chunkcount-- > 0){
		elfp_chunk_header_t type;
		if(elfp_read_safe(start,end,off,sizeof type,&type,tsk))
			return -EIO;
		off += sizeof type;
		switch(type)
		{
		case ELFP_CHUNK_STATE:
		{
			struct elfp_desc_state buf;
			struct elfp_state *state = elfp_alloc_state();
			if (!state)
				return -ENOMEM; /*TODO: free */
			state->prev = NULL;
			state->next = pol->states;
			if (pol->states) {
				pol->states->prev = state;
			}
			pol->states = state;
			if (elfp_read_safe(start, end,off, sizeof buf, &buf,tsk))
				return -EIO;
			off += sizeof buf;
			state->codelow = buf.low;
			state->codehigh = buf.high;
			state->id = buf.id;
			state->policy = pol;
			state->calls = NULL;
			state->data = NULL;
			state->context = elfp_os_context_new(tsk);
			elfp_os_copy_mapping(tsk, state->context,buf.low,buf.high);
		}
		case ELFP_CHUNK_CALL:
		{
			struct elfp_desc_call buf;
			struct elfp_call_transition *data = elfp_alloc_call_transition();
			if(!data)
				return -ENOMEM;
			if(elfp_read_safe(start,end,off,sizeof buf,&buf,tsk))
				return -EIO;
			off += sizeof buf;
			data->left = data->right = NULL;
			data->from = elfp_find_state_by_id(pol,buf.from);
			if(!data->from){
				return -EINVAL;
			}
			data->to = elfp_find_state_by_id(pol,buf.to);
			if(!data->to){
				return -EINVAL;
			}
			data->offset = buf.offset;
			data->parambytes = buf.parambytes;
			data->returnbytes = buf.returnbytes;

			elfp_insert_call_transition(data);
		}
		case ELFP_CHUNK_READWRITE:
		{
			struct elfp_desc_readwrite buf;
			struct elfp_data_transition *data = elfp_alloc_data_transition();
			if(!data)
				return -ENOMEM;
			if(elfp_read_safe(start,end,off,sizeof buf,&buf,tsk))
				return -EIO;
			off += sizeof buf;

			data->left = data->right = NULL;
			data->from = elfp_find_state_by_id(pol,buf.from);
			if(!data->from){
				return -EINVAL;
			}
			data->to = elfp_find_state_by_id(pol,buf.to);
			if(!data->to){
				return -EINVAL;
			}
			data->low = buf.low;
			data->high = buf.high;
			data->type = buf.type & ELFP_RW_ALL;
			elfp_insert_data_transition(data);
		}
		default:
			return -1; /* terminate process, we have an unknown */
		}
	}
	elfp_task_set_policy(tsk,pol);
	return 0;
}
int elfp_destroy_policy(struct elf_policy *policy)
{
	if(0 == elfp_policy_get_refcount(policy)){
		elfp_os_errormsg("elfp_free_policy: Tried to free elf policy that is still in use");
		return -EINVAL;
	}
	while(policy->states){
		struct elfp_state *state;
		elfp_os_free_context(policy->states->context);
		/* Free each without allocating. Bad runtime (?)*/
		while(policy->states->data){
			struct elfp_data_transition **pp = &(policy->states->data);
			while((*pp)->left)
				pp = &(*pp)->left;
			while((*pp)->right)
				pp = &(*pp)->right;
			elfp_free_data_transition(*pp);
			*pp = NULL;
		}
		while(policy->states->calls){
			struct elfp_call_transition **pp = &(policy->states->calls);
			while((*pp)->left)
				*pp = (*pp)->left;
			while((*pp)->right)
				*pp = (*pp)->right;
			elfp_free_call_transition(*pp);
			*pp=NULL;
		}
		state = policy->states;
		policy->states = policy->states->next;
		elfp_free_state(state);
	}
	elfp_free_policy(policy);
	return 0;
}
