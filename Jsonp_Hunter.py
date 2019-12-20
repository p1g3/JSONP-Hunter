#coding:utf-8
from burp import IBurpExtender
from burp import IScannerCheck
from burp import IHttpRequestResponse
import re

jsonp_dicts = ['callback','cb','jsonp','jsonpcallback','jsonpcb','jsonp_cb','call','jcb','json']

print('Author：P1g3')
print('Blog：p1g3.github.io')
print(' ')

jsonp_url = list()

class BurpExtender(IBurpExtender, IScannerCheck,IHttpRequestResponse):

    def registerExtenderCallbacks(self, callbacks):
        # 保留对回调对象的引用
        self._callbacks = callbacks

        # 获取扩展助手对象
        self._helpers = callbacks.getHelpers()

        # 设置扩展名
        callbacks.setExtensionName('Jsonp Hunter')

        # 将自己注册为自定义扫描器检查
        callbacks.registerScannerCheck(self)

    # 被动扫描时，执行
    def processHttpMessage(self, toolFlag, messageIsRequest, messageinfo):
        if toolFlag == 4 :
            if messageIsRequest: #判断请求是否正在进行中
                return

    def doPassiveScan(self, baseRequestResponse):
        #print(dir(self))
        #request相关

        request = baseRequestResponse.getRequest()
        analyzedRequest, reqBodys,req_headers, req_method, req_parameters = self.getRequestInfo(request)
        params = req_headers[0].split(' ')[1]
        httpService = baseRequestResponse.getHttpService()
        port = httpService.getPort()
        host = httpService.getHost()
        protocol = httpService.getProtocol()
        # print(port)
        # print(host)

        #response相关
        response = baseRequestResponse.getResponse()
        res_headers,res_status_code,res_mime_type,res_bodys = self.getResponseInfo(response)
        if req_headers[0].startswith('GET'):
                jsonp_status = False
                link = req_headers[0].split(' ')[1]
                host = req_headers[1].split(' ')[1]
                """
                第一种情况：即请求中包含的value，在返回包内以value({.*?})的形式出现，可能会产生误报，因为并没有判断是否在开头出现。
                """
                params = req_headers[0].split(' ')[1]
                params = params.split('?')
                if(len(params)>1): #确认请求的url为xxx.xxx?xxx 而不是xxx.xxx
                    if('&' in params[1]): #判断是否存在多个key=>value
                        params = params[1].split('&')
                        if(len(params))>0:
                            for value in params:
                                value = value.strip()
                                if value != '':
                                    if '=' in value:
                                        value = value.split('=')[1]
                                        pattern = value + '\(\{.*?\}\)'
                                        try:
                                            result = re.findall(pattern,res_bodys,re.S)
                                        except:
                                            result = []
                                        if result!=[]:
                                            url = protocol+'://'+host+link
                                            if url not in jsonp_url:
                                                print('*'*30+'JSONP FIND' + '*' * 30)
                                                print('[+]URL：{} VALUE：{}'.format(url,value))
                                                print('*'*70)
                                                print(' ')
                                                with open('jsonp.txt','a+') as f:
                                                    f.write(url+'\n')
                                                jsonp_url.append(url)
                                                jsonp_status = True
                    else:
                        if '=' in str(params[1]):
                            value = params[1].split('=')[1]
                            value = value.strip()
                            if value!='':
                                pattern = value + '\(\{.*?\}\)'
                                try:
                                    result = re.findall(pattern,res_bodys,re.S)
                                except:
                                    pass
                                if result!=[]:
                                    url = protocol+'://'+host+link
                                    if url not in jsonp_url:
                                        print('*'*30+'JSONP FIND' + '*' * 30)
                                        print('[+]URL：{} VALUE：{}'.format(url,value))
                                        print('*'*70)
                                        print(' ')
                                        with open('jsonp.txt','a+') as f:
                                            f.write(url+'\n')
                                        jsonp_url.append(url)
                                        jsonp_status = True
                """
                第二种情况：即请求包中的value并没有以value({.*?})的形式出现在返回包中，此时使用自定义字典进行rebuild，重新发包探测并判断。
                """
                if len(params)<=1 or not jsonp_status:
                    againReqHeaders = req_headers
                    #print(againReqHeaders[0])
                    #print(reqHeaders)
                    copyparams = params[0]
                    if len(params) == 1:
                        for _ in jsonp_dicts:
                            # againReqHeaders = reqHeaders
                            # print(againReqHeaders)
                            #print(params[0])
                            againReqHeaders[0] = req_headers[0].replace(params[0],copyparams + '?' + _ + '=p1g3')
                            params[0] = copyparams + '?' + _ + '=' + 'p1g3'

                            againReq = self._helpers.buildHttpMessage(againReqHeaders, reqBodys)
                            ishttps = False
                            if protocol == 'https':
                                ishttps = True
                            againRes = self._callbacks.makeHttpRequest(host, port, ishttps, againReq)
                            link = againReqHeaders[0].split(' ')[1]
                            host = againReqHeaders[1].split(' ')[1]
                            analyzedrep = self._helpers.analyzeResponse(againRes)
                            againResBodys = againRes[analyzedrep.getBodyOffset():].tostring()
                            result = re.findall('p1g3\(\{.*?\}\)',againResBodys,re.S)
                            if result!=[]:
                                url = protocol+'://'+host+link
                                if url not in jsonp_url:
                                    print('*'*30+'JSONP FIND' + '*' * 30)
                                    print('[+]URL：{} VALUE：{}'.format(url,'p1g3'))
                                    print('*'*70)
                                    print(' ')
                                    with open('jsonp.txt','a+') as f:
                                        f.write(url+'\n')
                                    jsonp_url.append(url)
                                    break
                            #print(againReqHeaders[0])
                            #print(againReqHeaders[0])
                            #print(reqHeaders)
                    else:
                        try:
                            params = req_headers[0].split(' ')[1]
                            copyparams = params
                            for _ in jsonp_dicts:
                                againReqHeaders[0] = req_headers[0].replace(params,copyparams+'&'+_+'=p1g3')
                                params = req_headers[0].split(' ')[1]

                                againReq = self._helpers.buildHttpMessage(againReqHeaders, reqBodys)
                                ishttps = False
                                if protocol == 'https':
                                    ishttps = True
                                againRes = self._callbacks.makeHttpRequest(host, port, ishttps, againReq)
                                link = againReqHeaders[0].split(' ')[1]
                                host = againReqHeaders[1].split(' ')[1]
                                #print(againReqHeaders)
                            # print(reqBodys)
                                analyzedrep = self._helpers.analyzeResponse(againRes)
                                againResBodys = againRes[analyzedrep.getBodyOffset():].tostring()
                                result = re.findall('p1g3\(\{.*?\}\)',againResBodys,re.S)
                                if result!=[]:
                                    url = protocol+'://'+host+link
                                    if url not in jsonp_url:
                                        print('*'*30+'JSONP FIND' + '*' * 30)
                                        print('[+]URL：{} VALUE：{}'.format(protocol+'://'+host+link,'p1g3'))
                                        print('*'*70)
                                        print(' ')
                                        with open('jsonp.txt','a+') as f:
                                            f.write(url+'\n')
                                        jsonp_url.append(url)
                                        break
                        except:
                            pass
    
    def getRequestInfo(self, request):
        analyzedRequest = self._helpers.analyzeRequest(request)
        reqBodys = request[analyzedRequest.getBodyOffset():].tostring()
        #print(type(analyzedRequest))
        #print(reqBodys)

        # 请求中包含的HTTP头信息
        req_headers = analyzedRequest.getHeaders()
        # 获取请求方法
        req_method = analyzedRequest.getMethod()  
        # 请求参数列表
        req_parameters = analyzedRequest.getParameters()

        return analyzedRequest, reqBodys,req_headers, req_method, req_parameters
    
    def getResponseInfo(self, response):
        analyzedResponse = self._helpers.analyzeResponse(response)

        # 响应中包含的HTTP头信息
        res_headers = analyzedResponse.getHeaders()
        # 响应中包含的HTTP状态代码
        res_status_code = analyzedResponse.getStatusCode()
        # 响应中返回的数据返回类型
        res_stated_mime_type = analyzedResponse.getStatedMimeType()
        # 响应中返回的正文内容
        res_bodys = response[analyzedResponse.getBodyOffset():].tostring() 

        return res_headers, res_status_code, res_stated_mime_type, res_bodys
    
    def doActiveScan(self, baseRequestResponse, insertionPoint):
        pass
