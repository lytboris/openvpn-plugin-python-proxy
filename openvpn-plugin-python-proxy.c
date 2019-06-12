/*
 * Copyright (C) 2018 Kaltashkin Eugene <aborche.aborche@gmail.com>
 * Copyright (C) 2019 Boris Lytochkin <lytboris@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * This file implements a python proxy for OpenVPN plugin module
 *
 * See the README file for build instructions.
 */

#define __EXTENSIONS__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <Python.h>

#include <openvpn-plugin.h>

#define PLUGIN_NAME "python-proxy"

struct hook_item {
	int	hook_id;
	const char *hook_name;
};

#define OPENVPN_HOOK(a) { OPENVPN_##a, "a" }

const struct hook_item plugin_hooks[] = {
	OPENVPN_HOOK(PLUGIN_UP),
	OPENVPN_HOOK(PLUGIN_DOWN),
	OPENVPN_HOOK(PLUGIN_ROUTE_UP),
	OPENVPN_HOOK(PLUGIN_IPCHANGE),
	OPENVPN_HOOK(PLUGIN_TLS_VERIFY),
	OPENVPN_HOOK(PLUGIN_AUTH_USER_PASS_VERIFY),
	OPENVPN_HOOK(PLUGIN_CLIENT_CONNECT),
	OPENVPN_HOOK(PLUGIN_CLIENT_DISCONNECT),
	OPENVPN_HOOK(PLUGIN_LEARN_ADDRESS),
	OPENVPN_HOOK(PLUGIN_CLIENT_CONNECT_V2),
	OPENVPN_HOOK(PLUGIN_TLS_FINAL),
	OPENVPN_HOOK(PLUGIN_ENABLE_PF),
	OPENVPN_HOOK(PLUGIN_ROUTE_PREDOWN),
};

/* Our context, where we keep our state. */
struct plugin_context {
	plugin_log_t log;
	const char *config_param;
	PyObject *pModule;
	PyObject *pFunc[OPENVPN_PLUGIN_N];
};

int
myStrLen(const char *envp[], int *envpsize)
{
	/* Calculate envp array elements length and array size */
	int i = 0;
	int totalsize = 0;
	for (i = 0; envp[i] != '\0'; i++) {
		totalsize += strlen(envp[i]);
	}

	*envpsize = totalsize;
	return i;
}

OPENVPN_EXPORT int
openvpn_plugin_open_v3(const int v3structver,
		       struct openvpn_plugin_args_open_in const *args,
		       struct openvpn_plugin_args_open_return *ret)
{
	struct plugin_context *context = NULL;

	/* Allocate our context */
	context = (struct plugin_context *)calloc(1, sizeof(struct plugin_context));

	/* consistent logging */
	plugin_log_t log = args->callbacks->plugin_log;
	context->log = log;

	/* Define plugin types which our script can serve */
	ret->type_mask = 0;

	/* Save parameters for plugin from openvpn config */
	if (args->argv[1])
		context->config_param = strdup(args->argv[1]);

	log(PLOG_DEBUG, PLUGIN_NAME, "openvpn-plugin-proxy: config_param=%s", context->config_param);

	/* Point the global context handle to our newly created context */
	ret->handle = (void *)context;


	/* Init Python interpreter */
	wchar_t *program = Py_DecodeLocale("openvpn-python-proxy", NULL);
	Py_SetProgramName(program);
	Py_Initialize();

	/* set module name for call python code */
	PyObject *pName = PyUnicode_FromString(context->config_param);
	context->pModule = PyImport_Import(pName);
	Py_DECREF(pName);

	if (context->pModule == NULL) {
		PyObject *ptype, *pvalue, *ptraceback;
		PyErr_Fetch(&ptype, &pvalue, &ptraceback);

		if (PyUnicode_Check(pvalue)) {
			log(PLOG_ERR, PLUGIN_NAME, "Failed to load python module and "
					"unicode encoding error occured a well so error message is lost (PyUnicode_Check)");
			return OPENVPN_PLUGIN_FUNC_ERROR;
		}

		PyObject *temp_bytes = PyUnicode_AsEncodedString(pvalue, "UTF-8", "strict"); // Owned reference
		if (temp_bytes != NULL) {
			log(PLOG_ERR, PLUGIN_NAME, "Failed to load python module: %s", PyBytes_AS_STRING(temp_bytes));
			Py_DECREF(temp_bytes);
		} else {
			log(PLOG_ERR, PLUGIN_NAME, "Failed to load python module and "
				"unicode encoding error occured a well so error message is lost (PyUnicode_AsEncodedString)");
		}
		return OPENVPN_PLUGIN_FUNC_ERROR;
	}

	/* Scan module for methods available and register them */
	for (int hook_num = 0; hook_num < OPENVPN_PLUGIN_N; hook_num++) {
		PyObject *pFunc = PyObject_GetAttrString(context->pModule, plugin_hooks[hook_num].hook_name);
		if (pFunc && PyCallable_Check(pFunc)) {
			context->pFunc[plugin_hooks[hook_num].hook_id] = pFunc;
			ret->type_mask |= OPENVPN_PLUGIN_MASK(plugin_hooks[hook_num].hook_id);
			log(PLOG_DEBUG, PLUGIN_NAME, "hook %s is enabled", plugin_hooks[hook_num].hook_name);
		} else {
			context->pFunc[plugin_hooks[hook_num].hook_id] = NULL;
			log(PLOG_DEBUG, PLUGIN_NAME, "hook %s is disabled", plugin_hooks[hook_num].hook_name);
		}
	}

	return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

OPENVPN_EXPORT int
openvpn_plugin_func_v3(const int version,
		       struct openvpn_plugin_args_func_in const *args,
		       struct openvpn_plugin_args_func_return *retptr)
{
	struct plugin_context *context = (struct plugin_context *)args->handle;
	PyObject *pArgs, *pValue, *pFunc;

	plugin_log_t log = context->log;

	/* Python function name for calling */
	int PyReturn = OPENVPN_PLUGIN_FUNC_ERROR;

	/* Build a Dict out of envp */
	PyObject *envDict = PyDict_New();
	PyObject *dKey, *dValue;
	for (const char **env_item = args->envp; *env_item; env_item++) {
		char *env_item_copy = strdup(*env_item);
		char *env_value = strtok(env_item_copy, "=");
		if (env_value == NULL) {
			log(PLOG_ERR, PLUGIN_NAME, "Environment variable parse error, = is not found in '%s'", *env_item);
			free(env_item_copy);
			continue;
		}
		dKey = PyUnicode_FromString(env_item_copy);
		dValue = PyUnicode_FromString(env_value);
		PyDict_SetItem(envDict, dKey, dValue);
		free(env_item_copy);
	}

	if (context->pModule == NULL) {
		log(PLOG_DEBUG, PLUGIN_NAME, "pModule is NULL");
		return OPENVPN_PLUGIN_FUNC_ERROR;
	}

	pFunc = context->pFunc[args->type];
	if (pFunc == NULL) {
		log(PLOG_DEBUG, PLUGIN_NAME, "pFunc is NULL");
		return OPENVPN_PLUGIN_FUNC_ERROR;
	}

	/* build args list */
	pArgs = PyTuple_New(1);
	/* pValue reference stolen here: */
	PyTuple_SetItem(pArgs, 0, envDict);
	pValue = PyObject_CallObject(pFunc, pArgs);
	Py_DECREF(pArgs);
	if (pValue != NULL) {
		long retval = PyLong_AsLong(pValue);
		log(PLOG_DEBUG, PLUGIN_NAME, "Result of call: %ld", retval);
		switch (retval) {
		case 0:
			PyReturn = OPENVPN_PLUGIN_FUNC_SUCCESS;
			break;
		case 1:
			PyReturn = OPENVPN_PLUGIN_FUNC_ERROR;
			break;
		case 2:
			PyReturn = OPENVPN_PLUGIN_FUNC_DEFERRED;
			break;
		default:
			PyReturn = OPENVPN_PLUGIN_FUNC_ERROR;
		}
		Py_DECREF(pValue);
	} else {
		PyErr_Print();
		log(PLOG_DEBUG, PLUGIN_NAME, "Call failed");
		return OPENVPN_PLUGIN_FUNC_ERROR;
	}

	return PyReturn;
}

OPENVPN_EXPORT void
openvpn_plugin_close_v1(openvpn_plugin_handle_t handle)
{
	struct plugin_context *context = (struct plugin_context *)handle;

	/* Shutdown Python interpreter */
	for (int hook_num = 0; hook_num < OPENVPN_PLUGIN_N; hook_num++)
		if (context->pFunc[hook_num])
			Py_DECREF(context->pFunc[hook_num]);
	Py_DECREF(context->pModule);
	Py_Finalize();

	free(context);
}
