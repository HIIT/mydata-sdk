#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  signed_request_auth.py
#  
# MIT License
#
# Copyright (c) 2016 Aleksi Palomäki
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#  
__author__ = "Aleksi Palomäki"
import time
import urlparse
from json import dumps
from requests.auth import AuthBase

from jwcrypto import jws

from json_builder import hash_params


class SignedRequest(AuthBase):
    def generate_authorization_header(self):
        # print(dumps(self.json_structure, indent=2))
        """
        Generates the actual PoP token and the string for Authorization header
        :return:
        """
        token = jws.JWS(dumps(self.json_structure).encode("utf-8"))
        token.add_signature(key=self.sign_key, alg=self.alg, header=self.header, protected=self.protected)
        authorization_header = "PoP {}".format(token.serialize(compact=True))
        return authorization_header

    def __init__(self,
                 token=None,  # Required
                 sign_method=False,
                 sign_url=False,
                 sign_path=False,
                 sign_query=False,
                 sign_header=False,
                 sign_body=False,
                 key=None,  # Required
                 alg=None,
                 protected=None,
                 header=None):

        """

        :param token:  Token for the "at" field                             (Required)
        :param sign_method: Do we add method to the signed part?            (Optional)
        :param sign_url: Do we add url to the signed part?                  (Optional)
        :param sign_path: Do we add path to the signed part?                (Optional)
        :param sign_query: Do we add query parameters to the signed part?   (Optional)
        :param sign_header: Do we add headers to the signed part?           (Optional)
        :param sign_body: Do we add content of body to the signed part?     (Optional)
        :param key: JWK used to sign the signed part                        (Required)
        :param alg: Algorithm used in key (Defaults to HS256)               (Optional)
        :param protected: Protected field for the signing                   (Optional)
        :param header: Header part for the signing                          (Optional)
        """
        if alg is None:
            if protected is None and header is None:
                protected = dumps({"typ": "JWS",
                                "alg": "HS256"})

        self.sign_method = sign_method
        self.sign_url = sign_url
        self.sign_path = sign_path
        self.sign_query = sign_query
        self.sign_header = sign_header
        self.sign_body = sign_body

        self.sign_key = key
        self.alg = alg
        self.header = header
        self.protected = protected

        if self.sign_key is None:
            raise TypeError("Key can't be type None.")

        self.json_structure = {
            "at": token,  # Required
            "ts": time.time()  # Optional but Recommended.
        }


    def __call__(self, r):
        """

        :param r: PreparedRequest object
        :return: PreparedRequest object
        """
        hasher = hash_params()
        # print(r.__dict__)

        if self.sign_query:
            params = urlparse.parse_qsl(urlparse.urlparse(r.url).query)
            # print(params)
            keys = []
            for item in params:
                keys.append(item[0])
            hash = hasher.hash(params)
            self.json_structure["q"] = [keys, hash]  # 'q' for query
        if self.sign_method:
            self.json_structure["m"] = r.method
        if self.sign_path:
            self.json_structure["p"] = urlparse.urlparse(r.url).path
        auth_header_has_content = r.headers.get("Authorization", False)
        if auth_header_has_content:  # TODO: Naive attempt to consider existing stuff in Authorization, I need to read more about requests to know if this could work.
            r.headers['Authorization'] = "{},{}".format(self.generate_authorization_header(),
                                                        r.headers['Authorization']).rstrip(",")
        else:
            r.headers['Authorization'] = self.generate_authorization_header()
        return r
