# ABOUT Byllud

IP resolution: resolves the IP address of the website provided.
Server response status: checks whether the request to the server was successful.
Site language: tries to detect the predominant language of the page content.
Forms: counts how many forms are present on the page.
User input fields: counts how many user input fields, such as text fields, password and e-mail, are present in the forms.
External links: counts how many external links are present on the page.
Hidden links: Counts how many hidden links are present on the page.
Cookies: Displays which cookies are being used on the site.
Content security policy header: displays the content security policy header, if present.
HTTP strict transport security header: Displays the HTTP strict transport security header, if present.
Possible administrator login page: searches for keywords that might indicate the presence of an administrator login page.
The code uses libraries such as requests to make HTTP requests, BeautifulSoup to parse the HTML of the page, langdetect to detect the language of the content and other libraries to format and display results.

It provides a command line interface where you can enter the URL of the site you want to analyze and then displays detailed results based on the characteristics mentioned above. The code also includes an ASCII graphical representation on the page.



