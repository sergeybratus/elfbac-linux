/* elfp.c
 * System calls to modify ELF policy
 * (c) 2011-2012 Julian Bangert
 * Released under the GPLv2/BSD dual license (except for the functions marked as such, which are just GPLv2)
*/
#include "elf_policy_linux.c"
int elfp_handle_instruction_address_fault(uintptr_t address,
		elfp_process_t *tsk,elfp_intr_state_t regs) {
	struct elfp_state *state = elfp_task_get_current_state(tsk);
	int retval = elfp_handle_data_address_fault(address,tsk,ELFP_RW_EXEC,regs);
	if (!retval) { /* Handle a call */
	  /* if(ELFP_TASK_STACKPTR(tsk) && ELFP_TASK_STACKPTR(tsk)->ret_offset == address){
			/* Handle a return: Pop stack frame and allow 
		  struct elfp_stack_frame *stack = ELFP_TASK_STACKPTR(tsk);
			elfp_os_copy_stack_bytes(stack->stack,stack->to->stack,stack->returnbytes);
			ELFP_TASK_STACKPTR(tsk) = stack->down;
			//elfp_free_stack_frame(stack);
			}*/
		struct elfp_call_transition *transition = state->calls;
		while(transition && (transition->offset != address)){
		  if(address < transition->offset)
		    transition = transition->left;
		  else
		    transition = transition->right;
		}
		if(unlikely(!transition)){
			return 0; /* Kill process */
		}
		else{
			elfp_os_change_context(tsk,transition->to,regs);/* TODO: Copy stack, handle return */
			return 1;
		}
	}
	return retval; /* Fail */
}
/* TODO handle overlapping, etc with only different accesses */
int elfp_handle_data_address_fault(uintptr_t address, elfp_process_t *tsk,int access_type,elfp_intr_state_t regs){
	struct elfp_state *state = elfp_task_get_current_state(tsk);
	struct elfp_data_transition *transition = state->data;
	while(transition && (transition->high < address || transition->low >address)){
		if(address < transition->low)
			transition = transition->left;
		else /* address > transition->high */
			transition = transition->right;
	}
	if(transition && transition->type & access_type){
		if(state == transition->to){
			elfp_os_copy_mapping(tsk,state->context, transition->low, transition->high);
			return 1;
		}
		else{
			elfp_os_change_context(tsk,transition->to,regs);
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
/*Insert into btree*/
static int elfp_insert_data_transition(struct elfp_data_transition *data){
	struct elfp_data_transition ** tree = &(data->from->data);
	while (*tree) {
		if ((*tree)->to > data->to)
			tree = &((*tree)->left);
		else if ((*tree)->to < data->to)
			tree = &((*tree)->right);
		else {/* We do not need to sort on high, but TODO: make sure they don't overlap */
			if ( data->low< (*tree)->low )
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
/*Insert into btree*/
static int elfp_insert_call_transition(struct elfp_call_transition *data){
	struct elfp_call_transition **tree = &(data->from->calls);
	while(*tree){
		if ((*tree)->to > data->to)
				tree = &((*tree)->left);
		else if((*tree)->to < data->to)
				tree =  &((*tree)->right);
		else {/* We do not need to sort on high, but TODO: make sure they don't overlap */
			if(  data->offset < (*tree)->offset)
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
static struct elfp_stack *elfp_find_stack_by_id(struct elf_policy *pol, elfp_id_t id){
	struct elfp_stack *retval = pol->stacks;
	while(retval && id!=retval->id)
		retval = retval->next;
	if(retval)
		return retval;
	else
		return NULL;
}
int elfp_parse_policy(uintptr_t start,uintptr_t size, elfp_process_t *tsk,elfp_intr_state_t regs){
	uintptr_t end = start +size;
	struct elf_policy *pol;
	struct elfp_desc_header hdr;
	struct elfp_state *state;
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
		/* Do not increment off, because the type is also in the descriptor*/
		switch(type)
		{
		case ELFP_CHUNK_STATE:
		{
			struct elfp_desc_state buf;
			state = elfp_alloc_state();
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
			//state->codelow = buf.low;
			//state->codehigh = buf.high;
			state->id = buf.id;
			state->policy = pol;
			state->calls = NULL;
			state->data = NULL;
			state->context = elfp_os_context_new(tsk);
			state->stack = NULL;
			if(!state->context)
				return -ENOMEM;
			//elfp_os_copy_mapping(tsk, state->context,buf.low,buf.high);
			break;
		}
		case ELFP_CHUNK_STACK:
		{
		  struct elfp_desc_stack buf;
		  struct elfp_stack *stack;
		  if(elfp_read_safe(start,end,off,sizeof buf,&buf,tsk))
		    return -EIO;
		  off += sizeof buf;
		  stack = elfp_os_alloc_stack(tsk,buf.size);
		  stack->id = buf.id;
		  if(!stack)
			  	  return -ENOMEM;
		  if(pol->stacks)
			  pol->stacks->prev = stack;
		  stack->next = pol->stacks;
		  pol->stacks = stack;
		  break;
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
			/*if(data->offset > data->to->codehigh || data->offset < data->to->codelow){
				elfp_os_errormsg("ELF call chunk invalid-> Offset not in target state\n");
				return -EINVAL;
			}*/
			elfp_insert_call_transition(data);
			break;
		}
		case ELFP_CHUNK_DATA:
		{
			struct elfp_desc_data buf;
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
			data->low = buf.addr1;
			if(data->type & ELFP_RW_SIZE)
			  data->high = buf.addr1 + buf.addr2;
			else 
			  data->high = buf.addr2;
			data->type = buf.type;
			elfp_insert_data_transition(data);
			break;
		}
		case ELFP_CHUNK_STACKACCESS:
		{
			struct elfp_desc_stackaccess buf;
			struct elfp_data_transition *data = elfp_alloc_data_transition();
			struct elfp_stack *stack;
			if(!data)
				return -ENOMEM;
			if(elfp_read_safe(start,end,off,sizeof buf,&buf,tsk)){
				elfp_free_data_transition(data);
				return -EIO;
			}
			off += sizeof buf;
			stack =  elfp_find_stack_by_id(pol,buf.stack);
			if(!stack){
				elfp_free_data_transition(data);
				elfp_os_errormsg("Stack not found\n");
				return -EIO;
			}
			data->type = buf.type & (~ELFP_RW_EXEC);
			data->from = elfp_find_state_by_id(pol,buf.from);
			if(!data->from){
				return -EINVAL;
			}
			data->to = elfp_find_state_by_id(pol,buf.to);
			if(!data->to){
				return -EINVAL;
			}
			data->low = stack->low;
			data->high = stack->high;
			elfp_insert_data_transition(data);
			break;
		}
		default:
			return -1; /* terminate process, we have an unknown */
		}
	}
	state = elfp_find_state_by_id(pol,1);
	if(!state){
		elfp_os_errormsg("elfp_parse_policy: Binary does not contain initial state 1\n");
		return -EINVAL;
	}
	elfp_task_set_policy(tsk,pol,state,regs);
	return 0;
}
int elfp_destroy_policy(struct elf_policy *policy)
{
	if(0 == elfp_policy_get_refcount(policy)){
		elfp_os_errormsg("elfp_free_policy: Tried to free elf policy that is still in use\n");
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
/* TODO: This breaks the links. At the moment this is for userspace use only*/
int elfp_print_policy(struct elf_policy *policy,elfp_print_function print){

	while(policy->states){
		struct elfp_state *state;
		/* Free each without allocating. Bad runtime (?)*/
		while(policy->states->data){
			struct elfp_data_transition **pp = &(policy->states->data);
			while((*pp)->left)
				pp = &(*pp)->left;
			while((*pp)->right)
				pp = &(*pp)->right;
			print("state_%d to state_%d ",(*pp)->from->id,(*pp)->to->id);
			if((*pp)->type & ELFP_RW_WRITE){
				print ("WRITE ");
			}
			if((*pp)->type & ELFP_RW_READ){
				print ("READ ");
			}
			if((*pp)->type & ELFP_RW_EXEC){
				print ("EXEC ");
			}
			print("0x%X - 0x%X",(*pp)->low,(*pp)->high);
			elfp_free_data_transition(*pp);
			*pp = NULL;
		}
		while(policy->states->calls){
			struct elfp_call_transition **pp = &(policy->states->calls);
			while((*pp)->left)
				*pp = (*pp)->left;
			while((*pp)->right)
				*pp = (*pp)->right;
			print("state_%d to state_%d call ",(*pp)->from->id,(*pp)->to->id);
			print("0x%X",(*pp)->offset);
			*pp=NULL;
		}
		state = policy->states;
		policy->states = policy->states->next;
	}
	return 0;
}
