typedef void* (*py_evaluator)(void*, void*, int throwflag);

 void *
 trampoline(void *ts, void *f,
            int throwflag, py_evaluator evaluator)
 {
     return evaluator(ts, f, throwflag);
 }