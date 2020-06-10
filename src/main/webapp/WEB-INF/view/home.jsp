<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form"%>
<%@ taglib prefix="security" uri="http://www.springframework.org/security/tags" %>
<html>

<head>
<title>Company Home Page</title>
</head>

<body>
	<h2>Company Home Page</h2>
	<hr>
	<security:authorize access="hasRole('Manager')">
	<a href="${pageContext.request.contextPath}/leaders">Leaders Meeting</a></security:authorize>|
	<security:authorize access="hasRole('ADMIN')">
	<a href="${pageContext.request.contextPath}/sysadmin">System Admin</a></security:authorize>
	<hr>

	Welcome to the XYZ company home page!
	<hr>
	USER   : <security:authentication property="principal.username"/>
	Role(s): <security:authentication property="principal.authorities"/>
<hr>	
	<form:form action="${pageContext.request.contextPath}/logout"
		method="POST" >
		<input type="submit" value="Logout"/>
	</form:form>
</body>

</html>