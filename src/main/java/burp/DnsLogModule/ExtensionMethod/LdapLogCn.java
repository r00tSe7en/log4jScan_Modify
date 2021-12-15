package burp.DnsLogModule.ExtensionMethod;

import java.io.PrintWriter;

import com.github.kevinsawicki.http.HttpRequest;
import burp.IBurpExtenderCallbacks;
import burp.DnsLogModule.ExtensionInterface.DnsLogAbstract;
//
public class LdapLogCn extends DnsLogAbstract {
    private IBurpExtenderCallbacks callbacks;

    private String dnslogDomainName = "http://ip:port/?api2=all";//JNDIMonitor监听http的api2接口
    private String temporaryDomainName = "ip:port";//JNDIMonitor监听ldap的接口


    public LdapLogCn(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;



        this.setExtensionName("LdapLogCn");

        this.init();
    }

    private void init() {
        String url = this.dnslogDomainName;
        String userAgent = "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36";

        HttpRequest request = HttpRequest.get(url);
        request.trustAllCerts();
        request.trustAllHosts();
        request.followRedirects(false);
        request.header("User-Agent", userAgent);
        request.header("Accept", "*/*");
        request.readTimeout(30 * 1000);
        request.connectTimeout(30 * 1000);

        int statusCode = request.code();
        if (statusCode != 200) {
            throw new RuntimeException(
                    String.format(
                            "%s 扩展-访问url-%s, 请检查本机是否可访问 %s",
                            this.getExtensionName(),
                            statusCode,
                            url));
        }

        this.setTemporaryDomainName(temporaryDomainName);

    }

    @Override
    public String getBodyContent() {
        String url = this.dnslogDomainName;
        String userAgent = "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36";

        HttpRequest request = HttpRequest.get(url);
        request.trustAllCerts();
        request.trustAllHosts();
        request.followRedirects(false);
        request.header("User-Agent", userAgent);
        request.header("Accept", "*/*");
        request.readTimeout(30 * 1000);
        request.connectTimeout(30 * 1000);

        String body = request.body();
        if (body.equals("[]")) {
            return null;
        }
        return body;
    }

    @Override
    public String export() {
        String str1 = String.format("<br/>============ldapLogExtensionDetail============<br/>");
        String str2 = String.format("ExtensionMethod: %s <br/>", this.getExtensionName());
        String str3 = String.format("ldapLogDomainName: %s <br/>", this.dnslogDomainName);
        String str4 = String.format("ldapLogRecordsApi: %s <br/>", this.dnslogDomainName);
        String str5 = String.format("ldapLogTemporaryDomainName: %s <br/>", this.getTemporaryDomainName());
        String str6 = String.format("=====================================<br/>");

        String detail = str1 + str2 + str3 + str4 + str5 + str6;

        return detail;
    }

    @Override
    public void consoleExport() {
        PrintWriter stdout = new PrintWriter(this.callbacks.getStdout(), true);

        stdout.println("");
        stdout.println("===========ldapLog扩展详情===========");
        stdout.println(String.format("被调用的插件: %s", this.getExtensionName()));
        stdout.println(String.format("ldapLog保存记录的api接口: %s", this.dnslogDomainName));
        stdout.println(String.format("ldapLog临时域名: %s", this.getTemporaryDomainName()));
        stdout.println("===================================");
        stdout.println("");
    }

    /**
     * 获取参数数据
     * 例如:
     * getParam("token=xx;Identifier=xxx;", "token"); 返回: xx
     *
     * @param d         被查找的数据
     * @param paramName 要查找的字段
     * @return
     */
    private static String getParam(final String d, final String paramName) {
        if (d == null || d.length() == 0)
            return null;

        String value = "test=test;" + d;

        final int length = value.length();
        int start = value.indexOf(';') + 1;
        if (start == 0 || start == length)
            return null;

        int end = value.indexOf(';', start);
        if (end == -1)
            end = length;

        while (start < end) {
            int nameEnd = value.indexOf('=', start);
            if (nameEnd != -1 && nameEnd < end
                    && paramName.equals(value.substring(start, nameEnd).trim())) {
                String paramValue = value.substring(nameEnd + 1, end).trim();
                int valueLength = paramValue.length();
                if (valueLength != 0)
                    if (valueLength > 2 && '"' == paramValue.charAt(0)
                            && '"' == paramValue.charAt(valueLength - 1))
                        return paramValue.substring(1, valueLength - 1);
                    else
                        return paramValue;
            }

            start = end + 1;
            end = value.indexOf(';', start);
            if (end == -1)
                end = length;
        }

        return null;
    }
}
