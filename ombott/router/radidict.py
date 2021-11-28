#!/usr/bin/env python3

import os
from enum import IntEnum
common_pref = os.path.commonprefix

__author__ = "Valery Kucherov <valq7711@gmail.com>"
__copyright__ = "Copyright (C) 2021 Valery Kucherov"
__license__ = "MIT"
__version__ = "0.0.3"


KEY = 0
IDX = 1
WEIGHT = 2  # doesn`t use at the moment
PARAMS = 3
FILTER = 4
IS_EXCLUSIVE = 5
HOOKS = 6
DATA = 7
OFFSET = 8


# mismatch types
class MismatchType(IntEnum):
    WHOLE = 1
    PARTIAL = 2
    TOKEN = 3
    FILTER = 4
    EXCLUSIVITY = 5


class RadiDictError(Exception):
    pass


class RadiDictKeyError(RadiDictError):
    def __init__(self, msg, **kw):
        super().__init__(msg)
        self.__err_args__ = kw

    def __getattr__(self, a):
        return self.__err_args__[a]


class RadiDict:
    def __init__(
        self, *,
        path_sep = '/',
        param_token = '\r',
        is_exclusive = False
    ):
        self.path_sep = path_sep
        self.param_token = param_token
        self.is_exclusive = is_exclusive
        self.root = self._make_node(key = '/')

    def _token_pos(self, s):
        ret = s.find(self.param_token)
        return ret if ret >= 0 else len(s)

    def _make_node(self, key, *,
                   idx = None, data = None, weight = 0,
                   children = None, params = None, filter = None,
                   is_exclusive = False, hooks = None):
        return [
            key,
            idx,
            weight,
            params or [],
            filter,
            is_exclusive,
            hooks,
            data,
            *(children or [])
        ]

    def _mount(self, pnode, child):

        keyerror = RadiDictKeyError
        ckey = child[KEY]

        if pnode[IDX]:
            has_token = pnode[IDX][-1] == self.param_token and pnode[IDX][-1]
            # if pnode has exclusive token child
            # it will be only one child at pnode[OFFSET]
            has_exclusive = has_token and pnode[OFFSET][IS_EXCLUSIVE]
            if has_exclusive:
                raise keyerror('can`t add `{ckey}` since exlusive token `{ptoken}` is already here')
            elif has_token and ckey == has_token:
                raise keyerror('can`t add `{ckey}` since token `{ptoken}` is already here')
            # maybe child is exclusive token
            elif child[IS_EXCLUSIVE]:
                raise keyerror('can`t add `{ckey}` since it is exclusive token but some keys are already here')
        # no children
        else:
            pnode[IDX] = ''

        if ckey == self.param_token:
            pnode.append(child)
            pnode[IDX] += ckey
        else:
            pnode.insert(OFFSET, child)
            pnode[IDX] = ckey[0] + pnode[IDX]
        pnode[WEIGHT] += 1
        return child

    def _split(self, pnode, split_idx: int = None, *, by_key = None):
        keyerror = RadiDictKeyError
        key = pnode[KEY]
        if by_key:
            split_idx = len(common_pref([key, by_key]))
            if not by_key or not key[split_idx:]:
                raise keyerror('something went wrong')
        new_key = key[:split_idx]
        key_rest = key[split_idx:]
        node = pnode[:]
        pnode[:] = self._make_node(
            key = new_key,
            idx = key_rest[0],
            weight = node[WEIGHT] + 1,
            children = [node]
        )
        node[KEY] = key_rest
        return pnode if not by_key else (pnode, split_idx)

    def _try_merge(self, pnode):
        if (
            pnode is self.root
            or pnode[DATA] or pnode[HOOKS]
            or not pnode[IDX] or len(pnode[IDX]) != 1
            or pnode[KEY] == self.param_token
            or pnode[IDX] == self.param_token
        ):  # i.e. child is token
            return

        child = pnode[OFFSET]
        new_key = pnode[KEY] + child[KEY]
        pnode[:] = child
        pnode[KEY] = new_key

    def _make_route(self, pnode, route_pattern, data, hooks, param_exclusions, param_filters, param_names):
        '''
        if route_pattern is sliced  param_exclusions, param_filters should be also sliced
        '''

        route = route_pattern
        TOKEN = self.param_token

        i = 0
        param_idx = 0
        while i < len(route):
            args = {}  # new node args
            route_rest = route[i:]
            key_len = route_rest.find(TOKEN)
            if key_len == 0:
                route_key = TOKEN
                key_len = 1
                args['is_exclusive'] = param_exclusions[param_idx]
                args['filter'] = param_filters[param_idx]
                # param_idx += 1
            elif key_len > 0:
                route_key = route_rest[: key_len]
            # no tokens
            else:
                route_key = route_rest
                key_len = len(route_key)

            args['key'] = route_key
            try:
                pnode = self._mount(pnode, self._make_node(**args))
                if route_key == TOKEN:
                    param_idx += 1
            except RadiDictKeyError as e:
                e.__err_args__['param_idx'] = param_idx
                raise

            i += key_len

        pnode[DATA] = data
        pnode[HOOKS] = hooks or None
        pnode[PARAMS] = param_names

    @staticmethod
    def params_unpack(params: dict):
        exclusions = []
        filters = []
        keys = []
        if params:
            for _e, _f in params.values():
                exclusions.append(_e)
                filters.append(_f)
            keys = list(params.keys())
        return exclusions, filters, keys

    def _set(self, pnode, route_pattern,
             *, data = None, hooks = None, params: dict = None, overwrite = True):
        '''
        params = {name:str :  [is_exclusive:boolean, filter:callable]}
        '''

        def error(msg):
            args = dict(
                matched = self._render_route(route_pattern[:ptr], prm_keys),
                route = self._render_route(route_pattern, prm_keys),
                raw_route = route_pattern,
                params = params,
                data = data,
                node = node
            )
            msg = msg.format(**args) + '\n ' + '\n  '.join([
                'matched:   {matched}',
                'route:     {route}'
            ]).format(**args)
            raise RadiDictKeyError(msg, **args)

        route = route_pattern
        prm_exclusions, prm_filters, prm_keys = self.params_unpack(params)
        node, mismatch, ptr, prm_idx, _ = self._match(route, prm_exclusions, prm_filters, pnode)
        if mismatch == MismatchType.EXCLUSIVITY:
            error('tokens exclusivity mismatch')
        elif mismatch == MismatchType.FILTER:
            error('tokens filter mismatch')
        elif mismatch == MismatchType.PARTIAL:
            ckey = route[ptr:]
            ckey = ckey[: self._token_pos(ckey)]
            node, split_idx = self._split(node, by_key=ckey)
            ptr += split_idx
            mismatch = False if ptr >= len(route) else MismatchType.WHOLE

        if not mismatch:
            for item_idx, item in [(DATA, data), (HOOKS, hooks)]:
                if item is None:
                    continue
                if node[item_idx] and not overwrite:
                    error('handler is already registered here')
                else:
                    node[item_idx] = item
            if data is not None:  # prevent to overwrite param keys by hooks
                node[PARAMS] = prm_keys
            return
        else:
            try:
                self._make_route(
                    node, route[ptr:], data, hooks,
                    prm_exclusions[prm_idx:], prm_filters[prm_idx:], prm_keys
                )
            except RadiDictKeyError as e:
                msg = e.args[0]
                msg = msg.format(
                    ckey = prm_keys[prm_idx + e.param_idx],
                    ptoken = '<param>'
                )
                error(f'Key error: {msg}')

    def _match(self, route_pattern, param_exclusions: list = None, param_filters: list = None, pnode = None):
        pnode = pnode if pnode is not None else self.root
        route = route_pattern
        TOKEN: str = self.param_token
        L: int = len(route)
        i = 0
        param_idx = 0
        mismatch = None
        key_end = 0
        stack = [pnode]
        is_exact = False
        while i < L:
            pnode_idx = pnode[IDX]
            c0 = route[i]
            kidx = 0
            for ic, c in enumerate(pnode_idx or []):
                if c == c0:
                    kidx = ic; break  # found!
            else:
                break  # not found - break while

            pnode = pnode[kidx + OFFSET]
            key = pnode[KEY]
            key_end = i + len(key)
            stack.append(pnode)
            if key == route[i: key_end]:
                if key == TOKEN:
                    if (
                        param_exclusions
                        and pnode[IS_EXCLUSIVE] != param_exclusions[param_idx]
                    ):
                        mismatch = MismatchType.EXCLUSIVITY
                        break  # while: fail
                    elif (
                        param_filters
                        and pnode[FILTER] != param_filters[param_idx]
                    ):
                        mismatch = MismatchType.FILTER
                        break  # while: fail

                    param_idx += 1
                i = key_end
            else:
                mismatch = MismatchType.PARTIAL
                break  # while: fail
        else:  # success
            is_exact = True

        if not is_exact and not mismatch:
            mismatch = MismatchType.WHOLE
        return pnode, mismatch, i, param_idx, stack

    # ------------------- [interface methods] --------------------------
    def add(self, route_pattern, data, params = None, *, overwrite = False):
        if isinstance(params, (list, tuple)):
            params = dict.fromkeys(params, [self.is_exclusive, None])
        return self._set(
            self.root, route_pattern,
            data = data, params = params, overwrite = overwrite
        )

    def add_hooks(self, route_pattern, hooks, params = None, *, overwrite = False):
        if isinstance(params, (list, tuple)):
            params = dict.fromkeys(params, [self.is_exclusive, None])
        return self._set(
            self.root, route_pattern,
            hooks = hooks, params = params, overwrite = overwrite
        )

    def remove(self, route_pattern, hooks_only=False):

        is_wildcard = False
        if route_pattern and route_pattern[-1] == '*':
            route_pattern = route_pattern[:-1]
            is_wildcard = True
            if hooks_only:
                raise RadiDictError('Can`t remove hooks by wildcard')

        node, mismatch, ptr, prm_idx, stack = (
            self._match(route_pattern, pnode = self.root)
        )

        if is_wildcard and (
            not mismatch
            or mismatch == MismatchType.PARTIAL
            and node[KEY].startswith(route_pattern[ptr:])
        ):
            node[IDX] = None
            del node[OFFSET:]
        elif mismatch:
            return

        if hooks_only and node[DATA] is not None:
            node[HOOKS] = None
            return

        stack.reverse()
        assert node is stack[0]
        node[DATA] = None
        node[PARAMS] = []
        key0_to_del = None
        for node in stack:
            if key0_to_del:
                kidx = node[IDX].find(key0_to_del)
                if kidx < 0:
                    raise RadiDictError(
                        'critical error: router seems to be corrupted'
                    )
                node[IDX] = node[IDX].replace(key0_to_del, '')
                del node[OFFSET + kidx]
                self._try_merge(node)
            if not (node[DATA] or node[IDX]):
                key0_to_del = node[KEY][0]
            else:
                break

    def get(self, route, allow_partial=False):
        # local constants
        TOKEN: str = self.param_token
        PATH_SEP: str = self.path_sep
        L: int = len(route)

        pnode = self.root
        params = []
        hooks = pnode[HOOKS]
        hooks = [[0, hooks]] if hooks else []
        look_back = []
        do_look_back = False
        selector = None
        i = 0
        while True:
            while i < L:
                idx = pnode[IDX]
                if not idx:
                    # there are no children
                    break  # while

                kidx = None
                if do_look_back:
                    do_look_back = False
                    c = idx[-1]
                else:
                    c0 = route[i]
                    for ic, c in enumerate(idx):
                        if c == c0:
                            kidx = ic; break  # found!

                if kidx is None:  # not found
                    # maybe token or look_back
                    if c == TOKEN:
                        token_node = pnode[-1]
                        filter = token_node[FILTER]
                        if filter:
                            param_value, j, selector = filter(route[i:])
                            j += i
                        else:
                            j = i
                            while j < L:
                                if route[j] == PATH_SEP:
                                    break
                                j += 1
                            param_value = route[i:j]

                        if param_value is not None:
                            params.append(param_value)
                            i = j
                            pnode = token_node
                            h = pnode[HOOKS]
                            if h:
                                hooks.append([i, h])
                            if selector is not None:
                                look_back.append(
                                    [route, pnode, i, L, params[:], hooks[:], False]
                                )
                                route = str(selector) + route[i:]
                                i = 0
                                L = len(route)
                                selector = None
                            continue
                        else:
                            break  # while
                    else:
                        break

                # regular logic
                if idx[-1] == TOKEN:
                    look_back.append(
                        [route, pnode, i, L, params[:], hooks[:], True]
                    )
                pnode = pnode[OFFSET + kidx]
                key = pnode[KEY]
                key_end = i + len(key)
                if key == route[i: key_end]:
                    i = key_end
                    h = pnode[HOOKS]
                    if h:
                        hooks.append([i, h])
                else:
                    break  # while

            else:  # while-postprocessing
                if pnode[DATA]:
                    return (
                        pnode[DATA],
                        dict(
                            param_keys = pnode[PARAMS],
                            param_values = params,
                            hooks = hooks
                        )
                    )
                # if there is no data
                # this is partial match => try look_back

            if look_back:
                route, pnode, i, L, params, hooks, look_type = look_back.pop()
                do_look_back = look_type
            else:
                return None if not allow_partial else (
                    None,
                    dict(
                        param_values = params,
                        hooks = hooks,
                        partial = route[:i]
                    )
                )

    # ---------------- [helpers] --------------------------
    def _render_route(self, route, params):
        if not params:
            return route
        for p in params:
            route = route.replace(self.param_token, f':{p or "noname"}', 1)
        return route

    def _routes_iter(self, pnode = None, startswith = None, yield_hooks = False):
        pnode = pnode or self.root
        prefix_stack = []
        if startswith:
            node, mismatch, ptr, _, prefix_stack = self._match(startswith, pnode = pnode)
            if (
                not mismatch
                or mismatch == MismatchType.PARTIAL
                and node[KEY].startswith(startswith[ptr:])
            ):
                pnode = node
                del prefix_stack[-1]
            else:
                return []

        rec = [
            pnode,  # path
            len(pnode[IDX] or ''),
            0,  # cur child index
        ]
        path = [pnode]
        stack = [rec]
        while stack:
            pnode, L, i = stack[-1]
            if i < L:
                cnode = pnode[i + OFFSET]
                L = len(cnode[IDX] or '')
                stack[-1][2] = i + 1
                path.append(cnode)
                stack.append([
                    cnode,
                    L,
                    0
                ])
            else:
                if pnode[DATA] or yield_hooks and pnode[HOOKS]:
                    yield prefix_stack + path
                stack.pop()
                path.pop()
