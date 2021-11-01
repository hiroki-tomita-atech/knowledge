<%@page import="org.support.project.web.util.JspUtil"%>
<%@page import="org.support.project.knowledge.logic.SystemConfigLogic"%>
<%@page import="org.support.project.common.util.StringUtils"%>
<%@page pageEncoding="UTF-8" isELIgnored="false" session="false"%>
<%@taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions"%>
<%@taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt"%>

<% JspUtil jspUtil = new JspUtil(request, pageContext); %>


<c:import url="/WEB-INF/views/commons/layout/layoutMain.jsp">

<c:param name="PARAM_HEAD">
</c:param>

<c:param name="PARAM_SCRIPTS">
<script type="text/javascript" src="<%= jspUtil.mustReloadFile("/js/signin-form.js") %>"></script>
</c:param>

<c:param name="PARAM_CONTENT">
<h4 class="title"><%= jspUtil.label("label.login") %></h4>

    <div class="container">
        <%= jspUtil.label("knowledge.auth.signin.description") %>
        <form class=""
            action="<%=request.getContextPath()%>/signin"
            name="login" method="post">

            <% if (!StringUtils.isEmpty(request.getAttribute("page"))
                    && !"/open.knowledge/list".equals(request.getAttribute("page"))) { %>
                <div class="form-group">
                    <div class="">
                    <%= jspUtil.label("knowledge.auth.description") %>
                    </div>
                </div>
            <% } %>

            <c:if test="${loginError}">
                <div class="form-group">
                    <div class="">
                        <div class="alert alert-danger alert-dismissible" role="alert">
                        <button type="button" class="close" data-dismiss="alert" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                        <%= jspUtil.label("message.login.error") %>
                        </div>
                    </div>
                </div>
            </c:if>
            <input type="hidden" name="page" value="<%= jspUtil.out("page") %>" id="page">

            <div class="form-group">
                <input id="login-btn" type="image" src="<%=request.getContextPath()%>/images/google-btn/btn_google_signin_dark_normal_web.png" />
            </div>

        </form>

    </div>

</c:param>

</c:import>

