import easygui
import re, sys, base64, requests
from bs4 import BeautifulSoup

## test-abuse

### Get request to McAfee online scan
def setup():
    headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'Accept-Language': 'fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7'
    }

    base_url = 'http://www.trustedsource.org/sources/index.pl'
    r = requests.get(base_url, headers=headers)

    bs = BeautifulSoup(r.content, "html.parser")
    form = bs.find("form", { "class" : "contactForm" })
    token1 = form.find("input", {'name': 'e'}).get('value')
    token2 = form.find("input", {'name': 'c'}).get('value')

    headers['Referer'] = base_url
    return headers, token1, token2

### Post request submitting url to McAfee online scan
def lookup(headers, token1, token2, url):
    payload = {'e':(None, token1),
               'c':(None, token2),
               'action':(None,'checksingle'),
               'product':(None,'01-ts'),
               'url':(None, url)}

    r = requests.post('https://www.trustedsource.org/en/feedback/url', headers=headers, files=payload)

    bs = BeautifulSoup(r.content, "html.parser")
    #form = bs.find("form", { "class" : "contactForm" })
    table = bs.find("table", { "class" : "result-table" })
    td = table.find_all('td')
    categorized = td[len(td)-3].text
    category = td[len(td)-2].text[2:]
    risk = td[len(td)-1].text

    return categorized, category, risk

def convert_elm_html(filename): 

    num_lines = sum(1 for line in open(filename))  

    S = ""  
    with open(filename, "r") as f:  
        for i in range(0, num_lines-1):  
            if (re.findall("Content-Type: ", f.readline())):  
                i = i + 2  
                f.readline()  
                if(re.findall("Content-Transfer-Encoding: base64", f.readline())):  
                    f.readline()  
                    while(1):  
                        tmp = f.readline()+f.readline()  
                        if (re.findall("\n\n", tmp)):  
                            break  
                        S = S+tmp  

    data = base64.b64decode(S)
    html_content = str(data.decode("utf-8"))

    with open(filename+"_convert.html", "w", encoding="utf-8") as con_f:  
        con_f.write(html_content)  

    return html_content

if __name__ == "__main__":    

    msg ="How to get HTML mail content ?"
    title = "Selection choice"
    choices = ["Upload File (.eml)", "Copy/Paste HTML Content"]

    html_content = ""
    filename = ""

    while html_content == "":
        choice = easygui.choicebox(msg, title, choices)
        
        if choice == choices[0]:
            filename = easygui.fileopenbox(default="*.eml")    
            if filename: 
                html_content = convert_elm_html(filename)
        elif choice == choices[1]:    
            html_content = easygui.codebox("HTML content mail :", "Phishing mail analyzer")
        else:
            sys.exit(0)


    if not(easygui.ccbox("Are you sure there are no confidential data in this mail ?", "Warning !!! Please Confirm")):
        sys.exit(0)
    
    else: # No confidential data 
        easygui.msgbox("Convert to HTML and saved as *.html \n\n" + html_content[:400] + "\n\n ...to be continued", "Converter to HTML content")
        ### URL parser from HTML content
        urls = set(re.findall('https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', html_content))
    
        easygui.msgbox(str(urls) + "\n\n saved as 'urls.txt'", "Parser urls from HTML content")
        with open('urls.txt', 'w') as f:
            f.write('\n'.join(urls))

        headers, token1, token2 = setup()

        for url in urls:
            ### Scan each url on McAfee online scan (safe?)   
            categorized, category, risk = lookup(headers, token1, token2, url)
            easygui.msgbox('url: {0} | Status: {1} | Category: {2} | Risk: {3}'.format(url, categorized, category, risk), "McAffee online safety scan")
            with open('trustedsource.txt', 'a') as fi:
                fi.write('url: '+url+' | Status: '+categorized+' | Category: '+category+' | Risk: '+risk)
                fi.write('\n')
            

            ### Sanitize screenshot filename
            filename = re.sub('http://|https://|www.|.com|.fr', '', url)
            
            ### Take a screenshot for each webpage
            with open('screenshot-'+filename+'.jpg', 'wb') as f:
                f.write(requests.get('https://api.apiflash.com/v1/urltoimage?access_key=461580a111f046fdb8bee468e6787818&url='+url).content)

            ### test trendmicro WIP dans test.py
        
        easygui.msgbox("\n\n saved as 'trustedsource.txt'")
        easygui.msgbox("Bye :)", "See you soon") 
