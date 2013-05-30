/* elfp.c
 * System calls to modify ELF policy
 * (c) 2011-2012 Julian Bangert
 * Released under the GPLv2/BSD dual license (except for the functions marked as such, which are just GPLv2)
*/
#include "elf_policy_linux.c"
struct elfp_call_transition *elfp_os_find_call_transition(struct elfp_state *state,uintptr_t address){ /*FIXME:                   Make generic with macros */
  struct rb_node *node = state->calls.rb_node;
  while(node){
    struct elfp_call_transition * transition = container_of(node,struct elfp_call_transition,tree);
    if(address < transition->offset)
      node = node->rb_left;
    else if(address > transition->offset)
      node = node->rb_right;
    else
      return transition;
  }
  return NULL;
}
int elfp_handle_instruction_address_fault(uintptr_t address,
		elfp_process_t *tsk,elfp_intr_state_t regs) {
	struct elfp_state *state = elfp_task_get_current_state(tsk);
	int retval = elfp_handle_data_address_fault(address,tsk,ELFP_RW_EXEC,regs);
	if (retval)  /* Handle an instruction fetch that hasn't been
                        ported yet */
          return retval;
        /* Maybe it's a return?*/
        if(ELFP_TASK_STACKPTR(tsk) && ELFP_TASK_STACKPTR(tsk)->ret_offset == address)     { 
#if 0
          struct elfp_stack_frame *stack = ELFP_TASK_STACKPTR(tsk);
          //elfp_os_copy_stack_bytes(stack->stack,stack->to->stack,stack->returnbytes);
          ELFP_TASK_STACKPTR(tsk) = stack->down;
          elfp_free_stack_frame(stack);
          elfp_os_change_context(tsk,stack->trans->from,regs);
          return 1;
#endif
        }
        struct elfp_call_transition * transition = elfp_os_find_call_transition(state,address);
        if(!transition)
          return NULL;
        if(transition->returnbytes >=0) /*If returning will be allowed*/
          {
#if 0
            struct elfp_stack_frame *stack= elfp_alloc_stack_frame(); /*TODO check for oom conditions */
            /*TODO: Copy stack bytes */
            stack->down = ELFP_TASK_STACKPTR(tsk);
            stack->trans = transition;
            stack->ret_offset = elfp_os_ret_offset(regs,address);
            stack->returnbytes = transition->returnbytes;
            ELFP_TASK_STACKPTR(tsk)= stack;
#endif 
          }
        elfp_os_change_context(tsk,transition->to,regs);/* TODO: Copy stack, handle return */
        return 1;
}
struct elfp_data_transition *elfp_os_find_data_transition(struct elfp_state *state,uintptr_t address){
  elfp_tree_node *node = state->data.rb_node;
  while(node){
    struct elfp_data_transition *transition = container_of(node,struct elfp_data_transition,tree);
    if(address < transition->low)
      node=node->rb_left;
    else if(address > transition->high)
      node=node->rb_right;
    else 
      return node;
  }
  return NULL;
}
/* TODO handle overlapping, etc with only different accesses */
int elfp_handle_data_address_fault(uintptr_t address, elfp_process_t *tsk,int access_type,elfp_intr_state_t regs){
	struct elfp_state *state = elfp_task_get_current_state(tsk);
	struct elfp_data_transition *transition = elfp_os_find_data_transition(state,address);
	if(transition && transition->type & access_type){
		if(state == transition->to){ /* This will be forever
                                                allowed -> map permanently */
			elfp_os_copy_mapping(tsk,state->context, transition->low, transition->high,transition->type);
			return 1;
		}
		else{
                  /*FIXME: Allow access once?*/
                  elfp_os_change_context(tsk,transition->to,regs);
                  return 1;
		}
        }
	return 0;
}
/* code for parsing policies*/
inline int elfp_read_safe(uintptr_t start,uintptr_t end, uintptr_t offset, size_t s,void *buf,elfp_process_t *tsk){
	unsigned long tmp;
	if(offset< start)
		goto err;
	if(offset+s > end)
          goto err;
	while(s){
		tmp = elfp_read_policy(offset,buf,s,tsk);
		if(!tmp) goto err;
		s -= tmp;
		offset += tmp;
		buf += tmp;
	}
	return 0;
 err:
        elfp_os_errormsg("ELFBAC: Could not read %u bytes from userspace offset %p \n",s,start+offset);
        return -1;
}
/*Insert into btree*/
static int elfp_insert_data_transition(struct elfp_data_transition *data){
  struct rb_node **new = &(data->from->data.rb_node),*parent =NULL;  
  
  while(*new){
    struct elfp_data_transition *transition = container_of(*new,struct elfp_data_transition,tree);
    uintptr_t address = data->low;
    parent = *new;
    if(address < transition->low)
      new=&((*new)->rb_left);
    else if(address > transition->high)
      new=&((*new)->rb_right);
    else 
      return -EINVAL;
  }
  /*FIXME: Check against overlap with next*/
  rb_link_node(&data->tree, parent, new);
  rb_insert_color(&data->tree, &data->from->data);
  return 0;
}
/*Insert into btree*/
static int elfp_insert_call_transition(struct elfp_call_transition *data){
  struct rb_node **new = &(data->from->calls.rb_node),*parent =NULL;  
  uintptr_t address = data->offset;
  while(*new){
    struct elfp_call_transition *transition = container_of(*new,struct elfp_call_transition,tree);
    parent = *new;
    if(address < transition->offset)
      new=&((*new)->rb_left);
    else if(address > transition->offset)
      new=&((*new)->rb_right);
    else 
      return -EINVAL; /* Overlap */
  }
  rb_link_node(&data->tree, parent, new);
  rb_insert_color(&data->tree, &data->from->calls);
  return 0;
}
/*FIXME: Add a btree for this !*/
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
/*FIXME: Memory leaks with failures */
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
			state->calls = RB_ROOT;
			state->data = RB_ROOT;
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
			//data->left = data->right = NULL;
			data->from = elfp_find_state_by_id(pol,buf.from);
			if(!data->from){ 
                          elfp_os_errormsg("ELF policy transition referencing unknown source state %d\n",buf.from);
				return -EINVAL;
			}
			data->to = elfp_find_state_by_id(pol,buf.to);
			if(!data->to){
                          elfp_os_errormsg("ELF policy transition referencing unknown target state %d\n",buf.to);
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

			data->from = elfp_find_state_by_id(pol,buf.from);
			if(!data->from){
                          elfp_os_errormsg("ELF policy transition referencing unknown source state %d\n",buf.from);
                          return -EINVAL;
			}
			data->to = elfp_find_state_by_id(pol,buf.to);
			if(!data->to){
                          elfp_os_errormsg("ELF policy transition referencing unknown target state %d\n",buf.to);
                          return -EINVAL;
			}
			data->low = buf.addr1;
			if(data->type & ELFP_RW_SIZE)
			  data->high = buf.addr1 + buf.addr2;
			else 
			  data->high = buf.addr2;
			data->type = buf.type;
			if(data->high <= data->low){
                          elfp_os_errormsg("Invalid range in ELF policy transition\n");
			  return -EINVAL;
                        }
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
                  elfp_os_errormsg("Unknown chunk type %d in elfbac policy\n", type);
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
	if(0 != elfp_policy_get_refcount(policy)){
		elfp_os_errormsg("elfp_free_policy: Tried to free elf policy that is still in use\n");
		return -EINVAL;
	}
	while(policy->states){
		struct elfp_state *state;
                struct rb_node *iter, *next;
		elfp_os_free_context(policy->states->context);
                iter = rb_first(&policy->states->data);
                while(iter){
                  struct elfp_data_transition *pp = container_of(iter,struct elfp_data_transition,tree);
                  next = rb_next(iter);
                  rb_erase(iter, &policy->states->data); 
                  elfp_free_data_transition(pp);
                  iter= next;
                        
                }  
                iter = rb_first(&policy->states->calls);
                while(iter){
                  struct elfp_call_transition *pp = container_of(iter,struct elfp_call_transition,tree);
                  next = rb_next(iter);
                  rb_erase(iter,& policy->states->calls); 
                  elfp_free_call_transition(pp);
                  iter= next;
                        
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

	return 0;
}
