/*
   american fuzzy lop++ - python extension routines
   ------------------------------------------------

   Originally written by Michal Zalewski <lcamtuf@google.com>

   Now maintained by by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This is the real deal: the program takes an instrumented binary and
   attempts a variety of basic fuzzing tricks, paying close attention to
   how they affect the execution path.

 */

#include "afl-fuzz.h"

/* Python stuff */
#ifdef USE_PYTHON

int init_py() {

  Py_Initialize();
  u8* module_name = getenv("AFL_PYTHON_MODULE");

  if (module_name) {

#ifdef USE_PYTHON2
    PyObject* py_name = PyString_FromString(module_name);
#else
     PyObject* py_name = PyUnicode_FromString(module_name);
#endif

    py_module = PyImport_Import(py_name);
    Py_DECREF(py_name);

    if (py_module != NULL) {

      u8 py_notrim = 0;
      u8 py_no_pre_save_handler = 0;

      py_functions[PY_FUNC_INIT] = PyObject_GetAttrString(py_module, "init");
      py_functions[PY_FUNC_FUZZ] = PyObject_GetAttrString(py_module, "fuzz");
      py_functions[PY_FUNC_INIT_TRIM] =
          PyObject_GetAttrString(py_module, "init_trim");
      py_functions[PY_FUNC_POST_TRIM] =
          PyObject_GetAttrString(py_module, "post_trim");
      py_functions[PY_FUNC_TRIM] = PyObject_GetAttrString(py_module, "trim");
      py_functions[PY_PRE_SAVE_HANDLER] = PyObject_GetAttrString(py_module, "pre_save_handler");

      for (u8 py_idx = 0; py_idx < PY_FUNC_COUNT; ++py_idx) {

        if (!py_functions[py_idx] || !PyCallable_Check(py_functions[py_idx])) {

          if (py_idx >= PY_FUNC_INIT_TRIM && py_idx <= PY_FUNC_TRIM) {

            // Implementing the trim API is optional for now
            if (PyErr_Occurred()) PyErr_Print();
            py_notrim = 1;

          } else if(py_idx == PY_PRE_SAVE_HANDLER) {

            // Implementing the PY_PRE_SAVE_HANDLER API is optional for now
            if (PyErr_Occurred()) PyErr_Print();
            py_no_pre_save_handler = 1;

          } else {

            if (PyErr_Occurred()) PyErr_Print();
            fprintf(stderr,
                    "Cannot find/call function with index %d in external "
                    "Python module.\n",
                    py_idx);
            return 1;

          }

        }

      }

      if (py_notrim) {

        py_functions[PY_FUNC_INIT_TRIM] = NULL;
        py_functions[PY_FUNC_POST_TRIM] = NULL;
        py_functions[PY_FUNC_TRIM] = NULL;
        WARNF(
            "Python module does not implement trim API, standard trimming will "
            "be used.");

      }

      if (py_no_pre_save_handler) {
        py_functions[PY_PRE_SAVE_HANDLER] = NULL;
        WARNF(
            "Python module does not implement prev_save_handler API, standard save_handler will "
            "be used.");
      } else {
        // assign pre_save_handler with py_pre_save_handler
        ACTF("pre_save_handler is enabled");
        pre_save_handler = py_pre_save_handler;
      }

      PyObject *py_args, *py_value;

      /* Provide the init function a seed for the Python RNG */
      py_args = PyTuple_New(1);
#ifdef USE_PYTHON2
      py_value = PyInt_FromLong(UR(0xFFFFFFFF));
#else
      py_value = PyLong_FromLong(UR(0xFFFFFFFF));
#endif
      if (!py_value) {

        Py_DECREF(py_args);
        fprintf(stderr, "Cannot convert argument\n");
        return 1;

      }

      PyTuple_SetItem(py_args, 0, py_value);

      py_value = PyObject_CallObject(py_functions[PY_FUNC_INIT], py_args);

      Py_DECREF(py_args);

      if (py_value == NULL) {

        PyErr_Print();
        fprintf(stderr, "Call failed\n");
        return 1;

      }

    } else {

      PyErr_Print();
      fprintf(stderr, "Failed to load \"%s\"\n", module_name);
      return 1;

    }

  }

  return 0;

}

void finalize_py() {

  if (py_module != NULL) {

    u32 i;
    for (i = 0; i < PY_FUNC_COUNT; ++i)
      Py_XDECREF(py_functions[i]);

    Py_DECREF(py_module);

  }

  Py_Finalize();

}

void fuzz_py(char* buf, size_t buflen, char* add_buf, size_t add_buflen,
             char** ret, size_t* retlen) {

  if (py_module != NULL) {

    PyObject *py_args, *py_value;
    py_args = PyTuple_New(2);
    py_value = PyByteArray_FromStringAndSize(buf, buflen);
    if (!py_value) {

      Py_DECREF(py_args);
      fprintf(stderr, "Cannot convert argument\n");
      return;

    }

    PyTuple_SetItem(py_args, 0, py_value);

    py_value = PyByteArray_FromStringAndSize(add_buf, add_buflen);
    if (!py_value) {

      Py_DECREF(py_args);
      fprintf(stderr, "Cannot convert argument\n");
      return;

    }

    PyTuple_SetItem(py_args, 1, py_value);

    py_value = PyObject_CallObject(py_functions[PY_FUNC_FUZZ], py_args);

    Py_DECREF(py_args);

    if (py_value != NULL) {

      if(!PyByteArray_Check(py_value)){
        PyErr_Print();
        FATAL("return value of fuzz() must be bytearray");
      }

      *retlen = PyByteArray_Size(py_value);
      *ret = malloc(*retlen);
      memcpy(*ret, PyByteArray_AsString(py_value), *retlen);
      Py_DECREF(py_value);

    } else {

      PyErr_Print();
      FATAL("Call failed\n");

    }

  }

}

size_t py_pre_save_handler(u8* data, size_t size, u8** new_data) {
  PyObject *py_args, *py_value;

  py_args = PyTuple_New(1);
  py_value = PyByteArray_FromStringAndSize(data, size);

  if (!py_value) {

    Py_DECREF(py_args);
    FATAL("Failed to convert arguments");

  }

  PyTuple_SetItem(py_args, 0, py_value);

  py_value = PyObject_CallObject(py_functions[PY_PRE_SAVE_HANDLER], py_args);
  Py_DECREF(py_args);

  if (py_value != NULL) {

    if(!PyByteArray_Check(py_value)){
      PyErr_Print();
      FATAL("return value of pre_save_handler must be bytearray");
    }

    u32 new_size = PyByteArray_Size(py_value);
    *new_data = (u8 *)malloc(new_size);
    memcpy(*new_data, PyByteArray_AsString(py_value), new_size);

    Py_DECREF(py_value);
    return new_size;

  } else {

    PyErr_Print();
    FATAL("Call failed");

  }

}

u32 init_trim_py(char* buf, size_t buflen) {

  PyObject *py_args, *py_value;

  py_args = PyTuple_New(1);
  py_value = PyByteArray_FromStringAndSize(buf, buflen);
  if (!py_value) {

    Py_DECREF(py_args);
    FATAL("Failed to convert arguments");

  }

  PyTuple_SetItem(py_args, 0, py_value);

  py_value = PyObject_CallObject(py_functions[PY_FUNC_INIT_TRIM], py_args);
  Py_DECREF(py_args);

  if (py_value != NULL) {
#ifdef USE_PYTHON2
    u32 retcnt = PyInt_AsLong(py_value);
#else
    u32 retcnt = PyLong_AsLong(py_value);
#endif
    Py_DECREF(py_value);
    return retcnt;

  } else {

    PyErr_Print();
    FATAL("Call failed");

  }

}

u32 post_trim_py(char success) {

  PyObject *py_args, *py_value;

  py_args = PyTuple_New(1);

  py_value = PyBool_FromLong(success);
  if (!py_value) {

    Py_DECREF(py_args);
    FATAL("Failed to convert arguments");

  }

  PyTuple_SetItem(py_args, 0, py_value);

  py_value = PyObject_CallObject(py_functions[PY_FUNC_POST_TRIM], py_args);
  Py_DECREF(py_args);

  if (py_value != NULL) {

#ifdef USE_PYTHON2
    u32 retcnt = PyInt_AsLong(py_value);
#else
    u32 retcnt = PyLong_AsLong(py_value);
#endif
    Py_DECREF(py_value);
    return retcnt;

  } else {

    PyErr_Print();
    FATAL("Call failed");

  }

}

void trim_py(char** ret, size_t* retlen) {

  PyObject *py_args, *py_value;

  py_args = PyTuple_New(0);
  py_value = PyObject_CallObject(py_functions[PY_FUNC_TRIM], py_args);
  Py_DECREF(py_args);

  if (py_value != NULL) {

    if(!PyByteArray_Check(py_value)){
      PyErr_Print();
      FATAL("return value of trim() must be bytearray");
    }

    *retlen = PyByteArray_Size(py_value);
    *ret = malloc(*retlen);
    memcpy(*ret, PyByteArray_AsString(py_value), *retlen);
    Py_DECREF(py_value);

  } else {

    PyErr_Print();
    FATAL("Call failed");

  }

}

u8 trim_case_python(char** argv, struct queue_entry* q, u8* in_buf) {

  static u8 tmp[64];
  static u8 clean_trace[MAP_SIZE];

  u8  needs_write = 0, fault = 0;
  u32 trim_exec = 0;
  u32 orig_len = q->len;

  stage_name = tmp;
  bytes_trim_in += q->len;

  /* Initialize trimming in the Python module */
  stage_cur = 0;
  stage_max = init_trim_py(in_buf, q->len);

  if (not_on_tty && debug)
    SAYF("[Python Trimming] START: Max %d iterations, %u bytes", stage_max,
         q->len);

  while (stage_cur < stage_max) {

    sprintf(tmp, "ptrim %s", DI(trim_exec));

    u32 cksum;

    char*  retbuf = NULL;
    size_t retlen = 0;

    trim_py(&retbuf, &retlen);

    if (retlen > orig_len)
      FATAL(
          "Trimmed data returned by Python module is larger than original "
          "data");

    write_to_testcase(retbuf, retlen);

    fault = run_target(argv, exec_tmout);
    ++trim_execs;

    if (stop_soon || fault == FAULT_ERROR) goto abort_trimming;

    cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

    if (cksum == q->exec_cksum) {

      q->len = retlen;
      memcpy(in_buf, retbuf, retlen);

      /* Let's save a clean trace, which will be needed by
         update_bitmap_score once we're done with the trimming stuff. */

      if (!needs_write) {

        needs_write = 1;
        memcpy(clean_trace, trace_bits, MAP_SIZE);

      }

      /* Tell the Python module that the trimming was successful */
      stage_cur = post_trim_py(1);

      if (not_on_tty && debug)
        SAYF("[Python Trimming] SUCCESS: %d/%d iterations (now at %u bytes)",
             stage_cur, stage_max, q->len);

    } else {

      /* Tell the Python module that the trimming was unsuccessful */
      stage_cur = post_trim_py(0);
      if (not_on_tty && debug)
        SAYF("[Python Trimming] FAILURE: %d/%d iterations", stage_cur,
             stage_max);

    }

    /* Since this can be slow, update the screen every now and then. */

    if (!(trim_exec++ % stats_update_freq)) show_stats();

  }

  if (not_on_tty && debug)
    SAYF("[Python Trimming] DONE: %u bytes -> %u bytes", orig_len, q->len);

  /* If we have made changes to in_buf, we also need to update the on-disk
     version of the test case. */

  if (needs_write) {

    s32 fd;

    unlink(q->fname);                                      /* ignore errors */

    fd = open(q->fname, O_WRONLY | O_CREAT | O_EXCL, 0600);

    if (fd < 0) PFATAL("Unable to create '%s'", q->fname);

    ck_write(fd, in_buf, q->len, q->fname);
    close(fd);

    memcpy(trace_bits, clean_trace, MAP_SIZE);
    update_bitmap_score(q);

  }

abort_trimming:

  bytes_trim_out += q->len;
  return fault;

}

#endif                                                        /* USE_PYTHON */

