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
                                          elfp_process_t *tsk,elfp_os_mapping map,elfp_intr_state_t regs) {
  struct elfp_state *state = elfp_task_get_current_state(tsk);
  struct elfp_call_transition * transition;
  int retval = elfp_handle_data_address_fault(address,tsk,ELFP_RW_EXEC,map,regs);
  if (retval)  /* Handle an instruction fetch that hasn't been
                  copied yet */
    return retval;
  /* Maybe it's a return?*/
  if(ELFP_TASK_STACKPTR(tsk) && ELFP_TASK_STACKPTR(tsk)->ret_offset == address)     { 
    struct elfp_stack_frame *stack = ELFP_TASK_STACKPTR(tsk);
    //elfp_os_copy_stack_bytes(stack->stack,stack->to->stack,stack->returnbytes);
    ELFP_TASK_STACKPTR(tsk) = stack->down;
    elfp_os_change_context(tsk,stack->trans->from,regs);
    elfp_free_stack_frame(stack);
    return 1;
  }
  transition = elfp_os_find_call_transition(state,address);
  if(!transition)
    return 0;
  if(transition->returnbytes >=0) /*If returning will be allowed*/
    {
      struct elfp_stack_frame *stack= elfp_alloc_stack_frame(); /*TODO check for oom conditions */
      if(!stack) goto err_oom;
      /*TODO: Copy stack bytes */
      stack->down = ELFP_TASK_STACKPTR(tsk);
      stack->trans = transition;
      stack->ret_offset = elfp_os_ret_offset(regs,address);
      stack->returnbytes = transition->returnbytes;
      ELFP_TASK_STACKPTR(tsk)= stack;
    }
  elfp_os_change_context(tsk,transition->to,regs);/* TODO: Copy stack, handle return */
  return 1;
 err_oom:
  BUG();
}
struct elfp_data_transition *elfp_os_find_data_transition(struct elfp_state *state,unsigned long tag){
  elfp_tree_node *node = state->data.rb_node;
  while(node){
    struct elfp_data_transition *transition = container_of(node,struct elfp_data_transition,tree);
    if(tag < transition->tag)
      node=node->rb_left;
    else if(tag > transition->tag)
      node=node->rb_right;
    else 
      return transition;
  }
  return NULL;
}
/* TODO handle overlapping, etc with only different accesses */
int elfp_handle_data_address_fault(uintptr_t address, elfp_process_t *tsk,int access_type,elfp_os_mapping map,elfp_intr_state_t regs){
  struct elfp_state *state = elfp_task_get_current_state(tsk);
  struct elfp_data_transition *transition = elfp_os_find_data_transition(state,elfp_os_mapping_tag(map));
  assert_is_pagetable_subset(state->context,tsk->mm);
  if(transition && transition->type & access_type){
    if(state == transition->to){ /* This will be forever
                                    allowed -> map permanently */
      if(!elfp_os_copy_mapping(tsk,state->context, map,transition->type))
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
  elfp_os_errormsg("ELFBAC: Could not read %lu bytes from userspace offset %p \n",s,(void*)(start+offset));
  return -1;
}
/*Insert into btree*/
static int elfp_insert_data_transition(struct elfp_data_transition *data){
  struct rb_node **new = &(data->from->data.rb_node),*parent =NULL;  
  
  while(*new){
    struct elfp_data_transition *transition = container_of(*new,struct elfp_data_transition,tree);
    parent = *new;
    if(data->tag < transition->tag)
      new=&((*new)->rb_left);
    else if(data->tag > transition->tag)
      new=&((*new)->rb_right);
    else {
      elfp_os_errormsg("Elfbac parse error: Already have data transition from %d to %d tag %lu\n", data->from->id, data->to->id, data->tag);
      return -EINVAL;
    }
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
    else {
      elfp_os_errormsg("Already have a call transition from %d to %d at offset %p\n",
                       data->from->id, data->to->id, (void *)data->offset);
      return -EINVAL; /* Overlap */
    }
  }
  rb_link_node(&data->tree, parent, new);
  rb_insert_color(&data->tree, &data->from->calls);
  return 0;
}
/*FIXME: Add a btree for this !*/
struct elfp_state *elfp_find_state_by_id(struct elf_policy * pol, elfp_id_t id){
  struct elfp_state *retval = pol->states;
  while(retval && id!=retval->id)
    retval = retval->next;
  if(retval)
    return retval;
  else
    return NULL;
}
/*FIXME: Memory leaks with failures */
int elfp_parse_policy(uintptr_t start,uintptr_t size, elfp_process_t *tsk,elfp_intr_state_t regs){
  int retval;
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
          state->id = buf.id;
          state->policy = pol;
          state->calls = RB_ROOT;
          state->data = RB_ROOT;
          state->context = elfp_os_context_new(tsk);
          if(!state->context)
            return -ENOMEM;
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
          retval = elfp_insert_call_transition(data);
          if(retval)
            return retval;
          break;
        }
      case ELFP_CHUNK_DATA:
        {
          struct elfp_desc_access buf;
          struct elfp_data_transition *data;
          if(elfp_read_safe(start,end,off,sizeof buf,&buf,tsk))
            return -EIO;
          off += sizeof buf;
          data = elfp_alloc_data_transition();
          if(!data)
            return -ENOMEM;
          
          data->from = elfp_find_state_by_id(pol,buf.from);
          if(!data->from){
            elfp_os_errormsg("ELF policy transition referencing unknown source state %d\n",buf.from);
            elfp_free_data_transition(data);
            return -EINVAL;
          }
          data->to = elfp_find_state_by_id(pol,buf.to);
          if(!data->to){
            elfp_os_errormsg("ELF policy transition referencing unknown target state %d\n",buf.to);
            elfp_free_data_transition(data);
            return -EINVAL;
          }          
          data->tag = buf.tag;
          data->type = buf.type;
          elfp_insert_data_transition(data);
          break;
        } 
      case ELFP_CHUNK_TAG:
        {
          struct elfp_desc_static_tag buf;
          if(elfp_read_safe(start,end,off,sizeof buf,&buf,tsk))
            return -EIO;
          off += sizeof buf;
          retval = elfp_os_tag_memory(tsk,buf.begin, buf.begin + buf.size,buf.tag);
          if(retval)
            return retval;
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
struct elfp_stack_frame * elfp_copy_stack(struct elfp_stack_frame *stack,struct elf_policy *newpol){
  struct elfp_stack_frame *new_top = NULL, *prev=NULL;
  while(stack){
    struct elfp_stack_frame *tmp = elfp_alloc_stack_frame();
    struct elfp_state *newstate;
    struct elfp_call_transition *newtrans;
    if(!tmp) goto err_oom;
    newstate  = elfp_find_state_by_id(newpol,stack->trans->from->id);
    BUG_ON(!newstate);
    newtrans = elfp_os_find_call_transition(newstate,stack->trans->offset);
    BUG_ON(!newtrans);
    *tmp = *stack;
    tmp->trans = newtrans;
    tmp->down = NULL;
    if(!new_top)
      new_top = tmp;
    if(prev)
      prev->down = tmp;
    prev = tmp;
    stack  = stack->down;
  }
  return new_top;
 err_oom:
  BUG();
  return NULL;
}
struct elf_policy *elfp_clone_policy(struct elf_policy *policy, elfp_process_t *tsk)

{
  struct elf_policy *new =  elfp_alloc_policy();
  struct elfp_state *state;
  if(!new)
    return NULL;
  elfp_task_acquire_policy(policy);
  elfp_os_atomic_init(&new->refs,0);
  new->states = NULL;
  for(state = policy->states;state;state= state->next){
    struct elfp_state *newstate = elfp_alloc_state();
    if(!newstate)
      goto out_oom;
    newstate->id = state->id;
    newstate->prev = NULL;
    newstate->next = new->states;
    newstate->policy = new;
    if(newstate->next)
      newstate->next->prev = newstate;
    new->states = newstate;
    newstate->calls = RB_ROOT;
    newstate->data  = RB_ROOT;
    newstate->context = elfp_os_context_new(tsk);
  }
  for(state = policy->states;state;state=state->next){
    struct rb_node *iter;
    struct elfp_state *newstate = elfp_find_state_by_id(new,state->id);
    BUG_ON(!newstate);
    for(iter = rb_first(&state->data);iter;iter= rb_next(iter)){
      struct elfp_data_transition *pp = container_of(iter,struct elfp_data_transition,tree);
      struct elfp_data_transition *newdata = elfp_alloc_data_transition();
      if(!newdata)
        goto out_oom;
      *newdata = *pp;
      //      newdata->tree  = RB_;
      newdata->from = newstate;
      newdata->to = elfp_find_state_by_id(new, pp->to->id);
      elfp_insert_data_transition(newdata);
    }  
    for(iter = rb_first(&state->calls);iter; iter= rb_next(iter)){
      struct elfp_call_transition *pp = container_of(iter,struct elfp_call_transition,tree); 
      struct elfp_call_transition *newdata = elfp_alloc_call_transition();
      if(!newdata)
        goto out_oom;
      *newdata = *pp;
      //      newdata->tree = RB_ROOT;
      newdata->from = newstate;
      newdata->to = elfp_find_state_by_id(new, pp->to->id);
      elfp_insert_call_transition(newdata);
    }
  }
  
  elfp_task_release_policy(policy);
  return new;
 out_oom: 
    elfp_destroy_policy(new);
    return NULL;
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
int elfp_print_policy(struct elf_policy *policy,struct elfp_state *cur){
  struct elfp_state *state;
  for(state=policy->states;state;state = state->next){
    struct rb_node *iter;
    elfp_os_errormsg("%sState %d\n", (cur == state)?"*": " ", state->id);
    for(iter=rb_first(&state->data);iter; iter=rb_next(iter)){
      struct elfp_data_transition *pp = container_of(iter,struct elfp_data_transition,tree);
      elfp_os_errormsg("\t %d->%d data\t%ld\t%x\n",pp->from->id,pp->to->id,pp->tag,pp->type);
    }  
    for(iter = rb_first(&state->calls);iter;iter=rb_next(iter)){
      struct elfp_call_transition *pp = container_of(iter,struct elfp_call_transition,tree);
      elfp_os_errormsg("\t %d->%d call\t%lx\t%d\t%d\n",pp->from->id,pp->to->id,pp->offset,pp->parambytes,pp->returnbytes);
    }
  }
  return 0;
}
