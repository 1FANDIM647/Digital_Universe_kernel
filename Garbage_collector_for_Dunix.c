#include <stdio.h>
#include <stdlib.h>

#define STACK_MAX_SIZE 256 
#define IGCT 8

typedef enum {
	INT
	TWIN
}oType;


typedef struct sObject
{
	oType type;
    unsigned char marked; 

    struct sObject* next;



	union
	{
		int vaule; 
	}


	struct 
	{
	 struct sObject*head;
	 struct sObject*tile;
	 // I realised  it  goddawn 


	};
};

typedef struct 
{
	sObject* stack[STACK_MAX_SIZE];
	int stackSize;

    Object* firstObject;
    
    int numObjects;


}vm;

void push(vm* vm , Object* vaule){

	vm ->stack[--vm->stackSize];
}

Object* pop(vm* vm) {
	return vm ->stack[--vm->stackSize];
}


vm* newVm() {

	vm* mainVM = (vm*)malloc(sizeof(vm));
	mainVM->stackSize = 0 ;
	mainVM->firstObject =Null;
	mainVM->numObjects=0;
	mainVM->maxObjects=IGCT;
	return mainVM;
}

Object*  newObject(vm* vm, oType type )
{
	if(vm->numObjects == vm->maxObjects) gc(vm);
	Object* object =(Object*) malloc(sizeof(Object));
	object->type = type;
	vm->maxObjects++;
	return object;




}


void pushInt(vm* vm, int intV)
{

	Object* object = newObject(vm, INT);
	object ->vaule = intV;
	push(vm, object);
}


Object* pushTwin(vm* vm)
{

	Object* object = newObject(vm, TWIN);
	object->tail = pop(vm);
	object->head = pop(vm);


	push(vm , object);
	return object;
}

void markALL(vm* vm)
{

	for (int i= 0 ; i< vm->stack; i++){
		mark(vm ->stack[i]);
	}
}

// Будет  отвечать, удалять объект или нет  , маркоем  его )))
void markALL(vm* vm )
{
      
    if (object->marked) return;
	object->marked = 1;
    
    if (object->type ==TWIN)
    {
    	mark(object->head);
    	mark(object->tail);
    }

}

void marksweep(vm* vm)
{
	Object** object =&vm->firstObject;
	while (*object)
	{
		if(!(*object)->marked)
		{
			Object* unreached =*object;
			*object =unreached->next;
			free(unreached);

			vm->numObjects--;
		}
		else
		{
			(*object)->marked = 0;
			object =&(*object)->next;
		}


	}



}



void gc()
{
 int numObjects = vm->numObjects;

 markALL(vm);
 marksweep(vm);

 vm->maxObjects =vm->numObjects * 2;

 printf("Delted %d objects , %d are left.\n",numObjects - vm->numObjects,vm->numObjects);

}


void first_test ()
{

	printf("1: Objects of stack have been saved  \n");
	vm* mainVM = newVm();
	pushInt(mainVM, 1);
	pushInt(mainVM, 2);

	gc(mainVM);
	freeVM(mainVM);
}



void seecond_test ()
{

	printf("1: Objects of stack have been saved  \n");
	vm* mainVM = newVm();
	pushInt(mainVM, 1);
	pushInt(mainVM, 2);

	gc(mainVM);
	freeVM(mainVM);
}








void printObj(Object * object)
{
	switch(object->type)
	{
		case INT:
		printf("%d",object->vaule );
		break;

		case TWIN:
		printf("(" );
		printObj(object->head);
		printf("," );
		printObj(object->tail);
		printf(")");
		break;

	}
}


int main(int argc, const char** argv){

  first_test();
  seecond_test();


	return 0 ;
}

