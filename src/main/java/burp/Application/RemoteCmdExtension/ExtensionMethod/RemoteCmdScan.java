package burp.Application.RemoteCmdExtension.ExtensionMethod;

import java.net.URL;
import java.util.Date;
import java.util.List;
import java.util.ArrayList;
import java.io.PrintWriter;

import burp.*;

import burp.CustomScanIssue;
import burp.DnsLogModule.DnsLog;
import burp.Bootstrap.YamlReader;
import burp.Bootstrap.CustomHelpers;
import burp.Bootstrap.BurpAnalyzedRequest;
import burp.Application.ExtensionInterface.AAppExtension;
import burp.CustomErrorException.TaskTimeoutException;

public class RemoteCmdScan extends AAppExtension {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private BurpAnalyzedRequest analyzedRequest;

    private DnsLog dnsLog;

    private YamlReader yamlReader;

    private List<String> payloads;

    private Date startDate;
    private int maxExecutionTime;

    private String sendDnsLogUrl;

    private ArrayList<String> keyArrayList = new ArrayList<>();
    private ArrayList<String> dnsLogUrlArrayList = new ArrayList<>();
    private ArrayList<IHttpRequestResponse> httpRequestResponseArrayList = new ArrayList<>();

    public RemoteCmdScan(IBurpExtenderCallbacks callbacks, BurpAnalyzedRequest analyzedRequest,
                         DnsLog dnsLog, YamlReader yamlReader, List<String> payloads,
                         Date startDate, Integer maxExecutionTime) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        this.analyzedRequest = analyzedRequest;

        this.dnsLog = dnsLog;

        this.yamlReader = yamlReader;

        this.payloads = payloads;

        this.startDate = startDate;
        this.maxExecutionTime = maxExecutionTime;

        this.setExtensionName("RemoteCmdScan");
        this.registerExtension();

        this.runExtension();
    }

    private void runExtension() {
        for (IParameter parameter : analyzedRequest.getEligibleParameters()) {
            for (String payload : this.payloads) {
                // 说明接收到了dnslog请求确定是FastJson
                if (this.isIssue()) {
                    return;
                }

                // 如果dnslog有内容但是 this.isIssue() 为false
                // 这可能是因为 请求发出去了 dnslog还没反应过来
                // 这种情况后面的循环就没必要了, 退出该循环
                // 等待二次验证即可
                // 判断程序是否运行超时
                Integer startTime = CustomHelpers.getSecondTimestamp(this.startDate);
                Integer currentTime = CustomHelpers.getSecondTimestamp(new Date());
                Integer runTime = currentTime - startTime;
                if (runTime >= this.maxExecutionTime) {
                    throw new TaskTimeoutException("scan task timed out");
                }

                // 实际业务处理
                this.remoteCmdDetection(parameter, payload);
            }
        }

        // 防止因为dnslog卡导致没有检测到的问题, 这里进行二次检测, 保证不会漏报
        // 睡眠一段时间, 给dnslog一个缓冲时间
        try {
            Thread.sleep(8000);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }

        // 开始进行二次验证
        String dnsLogBodyContent = this.dnsLog.run().getBodyContent();
        if (dnsLogBodyContent == null || dnsLogBodyContent.length() <= 0) {
            return;
        }

        // 这里进行二次判断
        for (int i = 0; i < this.keyArrayList.size(); i++) {
            // dnslog 内容匹配判断
            if (!dnsLogBodyContent.contains(this.keyArrayList.get(i))) {
                if ((i + 1) != this.keyArrayList.size()) {
                    continue;
                } else {
                    return;
                }
            }

            // 设置问题详情
            this.setIssuesDetail(this.httpRequestResponseArrayList.get(i), this.dnsLogUrlArrayList.get(i));
            return;
        }
    }

    private void remoteCmdDetection(IParameter parameter, String payload) {
        String key = CustomHelpers.randomStr(15);
        String dnsLogUrl = this.dnsLog.run().getTemporaryDomainName()+"/"+key;

        // 构造header头的payload
        List<String> newHeaders = new ArrayList<>();
        List<String> headers = this.yamlReader.getStringList("application.remoteCmdExtension.config.headers");
        if (headers != null && headers.size() >= 1) {
            for (int i = 0; i < headers.size(); i++) {
                newHeaders.add(headers.get(i) + ": " + payload.replace("dnslog-url", dnsLogUrl+'/'+(i + 1)  ));
            }
        }

        String newPayload = "";
        if (CustomHelpers.isJson(parameter.getValue())) {
            // 参数为json时的payload构造方法
            // 例如: a={"a":1,"b":"ccccc"}
            String jsonPayload = CustomHelpers.jsonStringValueReplace(parameter.getValue(), payload);
            String[] jsonPayloadList = jsonPayload.split("dnslog-url");
            for (int i = 0; i < jsonPayloadList.length; i++) {
                if (jsonPayloadList.length != (i + 1)) {
                    //newPayload += jsonPayloadList[i] + (i + 1) + "." + "json" + "." + dnsLogUrl;
                    newPayload += jsonPayloadList[i] + dnsLogUrl + "/" + "json" + "/" + (i + 1);
                } else {
                    newPayload += jsonPayloadList[i];
                }
            }
        } else {
            // 构造普通参数的payload
            newPayload = payload.replace("dnslog-url", dnsLogUrl);
        }

        // 发送请求
        //IHttpRequestResponse newHttpRequestResponse = analyzedRequest.makeHttpRequest(parameter, payload.replace("dnslog-url", dnsLogUrl), newHeaders);
        IHttpRequestResponse newHttpRequestResponse = analyzedRequest.makeHttpRequest(parameter, newPayload, newHeaders);

        // 相关变量设置
        this.keyArrayList.add(key);
        this.dnsLogUrlArrayList.add(dnsLogUrl);
        this.httpRequestResponseArrayList.add(newHttpRequestResponse);

        // dnslog 返回的内容判断
        String dnsLogBodyContent = this.dnsLog.run().getBodyContent();
        if (dnsLogBodyContent == null || dnsLogBodyContent.length() <= 0) {
            return;
        }

        // dnslog 内容匹配判断
        if (!dnsLogBodyContent.contains(key)) {
            return;
        }

        // 设置问题详情
        this.setIssuesDetail(newHttpRequestResponse, dnsLogUrl);
    }

    /**
     * 设置问题详情
     */
    private void setIssuesDetail(IHttpRequestResponse httpRequestResponse, String dnsLogUrl) {
        this.setIssueState(true);
        this.setHttpRequestResponse(httpRequestResponse);

        this.sendDnsLogUrl = dnsLogUrl;
    }

    @Override
    public IScanIssue export() {
        if (!this.isIssue()) {
            return null;
        }

        IHttpRequestResponse newHttpRequestResponse = this.getHttpRequestResponse();
        URL newHttpRequestUrl = this.helpers.analyzeRequest(newHttpRequestResponse).getUrl();

        String str1 = String.format("<br/>=============RemoteCmdExtension============<br/>");
        String str2 = String.format("ExtensionMethod: %s <br/>", this.getExtensionName());
        String str3 = String.format("sendDnsLogUrl: %s <br/>", this.sendDnsLogUrl);
        String str4 = String.format("=====================================<br/>");

        // dnslog 详情输出
        String str5 = this.dnsLog.run().export();

        // dnslog body内容输出
        String str6 = String.format("<br/>=============DnsLogBodyContent============<br/>");
        String str7 = this.dnsLog.run().getBodyContent();
        String str8 = String.format("<br/>=====================================<br/>");

        String detail = str1 + str2 + str3 + str4 + str5 + str6 + str7 + str8;

        String issueName = this.yamlReader.getString("application.remoteCmdExtension.config.issueName");

        return new CustomScanIssue(
                newHttpRequestUrl,
                issueName,
                0,
                "High",
                "Certain",
                null,
                null,
                detail,
                null,
                new IHttpRequestResponse[]{newHttpRequestResponse},
                newHttpRequestResponse.getHttpService()
        );
    }

    @Override
    public void consoleExport() {
        if (!this.isIssue()) {
            return;
        }

        IHttpRequestResponse newHttpRequestResponse = this.getHttpRequestResponse();
        URL newHttpRequestUrl = this.helpers.analyzeRequest(newHttpRequestResponse).getUrl();
        PrintWriter stdout = new PrintWriter(this.callbacks.getStdout(), true);

        stdout.println("");
        stdout.println("===========RemoteCmdExtension详情============");
        stdout.println("检测到有一个站点有命令执行并且ldap出网");
        stdout.println(String.format("负责检测的插件: %s", this.getExtensionName()));
        stdout.println(String.format("url: %s", newHttpRequestUrl));
        stdout.println(String.format("发送的ldapLogUrl: %s", this.sendDnsLogUrl));
        stdout.println("详情请查看-Burp Scanner模块-Issue activity界面");
        stdout.println("===================================");
        stdout.println("");

        stdout.println("");
        stdout.println("===========ldapLog正文内容============");
        stdout.println(this.dnsLog.run().getBodyContent());
        stdout.println("===================================");
        stdout.println("");

        // dnslog 控制台详情输出
        this.dnsLog.run().consoleExport();
    }
}
