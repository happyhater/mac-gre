#ifndef _GRE_LOCKS_H
#define _GRE_LOCKS_H

#include <kern/locks.h>


//extern lck_grp_attr_t	*gre_grp_attributes;

extern lck_grp_t	*gre_lck_grp;
extern lck_grp_t	*gre_ipf_lck_grp;
extern lck_grp_t	*gre_sc_lck_grp;

extern lck_attr_t	*gre_lck_attributes;
extern lck_attr_t	*gre_ipf_lck_attributes;
extern lck_attr_t	*gre_sc_lck_attributes;


extern int	gre_locks_init(void);
extern void	gre_locks_dispose(void);

#endif
