# Dig-for-windows
Dig DNS tools for windows not need install linux for use Dig command  for networking lab 
# Dig for Windows 🖥️

<p align="center">
  <img src="https://img.shields.io/badge/version-9.20.22-blue" alt="version">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="license">
  <img src="https://img.shields.io/badge/platform-Windows-lightgrey" alt="platform">
</p>

<p align="right">
  <a href="#arabic">العربية</a> | <a href="#english">English</a>
</p>

---

<h2 id="arabic" dir="rtl">🇩🇿 Dig for Windows – أداة DNS احترافية لويندوز</h2>

<p dir="rtl">
نسخة طبق الأصل من أداة <code>dig</code> الشهيرة في لينكس، تعمل على ويندوز بدون الحاجة إلى تثبيت بايثون أو أي مكتبات خارجية. تم تطويرها بواسطة <strong>abdo_hak47</strong> من الأغواط، الجزائر 🇩🇿.
</p>

<h3 dir="rtl">✨ المميزات</h3>
<ul dir="rtl">
  <li>✅ <strong>مستقلة تمامًا</strong> – ملف <code>.exe</code> واحد فقط.</li>
  <li>✅ <strong>تدعم جميع خيارات dig</strong> – <code>+short</code>, <code>+trace</code>, <code>+tcp</code>, إلخ.</li>
  <li>✅ <strong>مُثبِّت تلقائي</strong> – يضيف الأداة إلى <code>PATH</code> لتعمل من أي مكان.</li>
  <li>✅ <strong>لا تحتاج صلاحيات خاصة</strong> للتشغيل (باستثناء التثبيت).</li>
  <li>✅ <strong>خفيفة وسريعة</strong> – مبنية بـ Python ومجمعة بـ PyInstaller.</li>
</ul>

<h3 dir="rtl">📥 التحميل والتثبيت</h3>
<ol dir="rtl">
  <li>اذهب إلى <a href="../../releases">صفحة الإصدارات (Releases)</a>.</li>
  <li>حمّل <code>Dig-setup.exe</code> للتثبيت التلقائي، أو <code>dig.exe</code> للنسخة المحمولة.</li>
  <li><strong>للتثبيت:</strong> شغّل <code>Dig-setup.exe</code> كمسؤول واتبع الخطوات.</li>
  <li><strong>للاستخدام المحمول:</strong> ضع <code>dig.exe</code> في أي مجلد، وافتح موجه الأوامر منه.</li>
  <li>بعد التثبيت، افتح <code>cmd</code> وجرب الأمر: <code>dig google.com</code></li>
</ol>

<h3 dir="rtl">🛠️ أمثلة على الاستخدام</h3>
<pre dir="ltr">
dig google.com                 # استعلام A عادي
dig google.com MX              # سجلات البريد
dig -x 8.8.8.8                 # بحث عكسي
dig example.com +short         # إجابة مختصرة
dig example.com +trace         # تتبع مسار الاستعلام
</pre>

<h3 dir="rtl">🔧 البناء من المصدر</h3>
<p dir="rtl">إذا أردت بناء الملف التنفيذي بنفسك:</p>
<pre dir="ltr">
git clone https://github.com/abdo_hak47/dig-for-windows.git
cd dig-for-windows
build\build.bat
</pre>
<p dir="rtl">المتطلبات: Python 3.9+ مع تثبيت PyInstaller (سيتم تثبيته تلقائيًا).</p>

<h3 dir="rtl">👨‍💻 المؤلف</h3>
<p dir="rtl">
  <strong>abdo_hak47</strong><br>
  📍 الأغواط، الجزائر<br>
  🎓 طالب بجامعة عمار ثليجي<br>
  🐙 <a href="https://github.com/AHX47">GitHub</a>
</p>

<h3 dir="rtl">📜 الترخيص</h3>
<p dir="rtl">هذا المشروع مرخص تحت <a href="https://github.com/AHX47/Dig-for-windows/blob/main/License.txt">MIT License</a> – لك مطلق الحرية في استخدامه وتعديله.</p>

<hr>

<h2 id="english">🇬🇧 Dig for Windows – Standalone DNS Tool</h2>

<p>
A faithful Windows port of the famous BIND <code>dig</code> utility. No Python, no dependencies – just a single executable. Developed by <strong>abdo_hak47</strong> from Laghouat, Algeria 🇩🇿.
</p>

<h3>✨ Features</h3>
<ul>
  <li>✅ <strong>Standalone</strong> – Single <code>.exe</code> file.</li>
  <li>✅ <strong>Full dig compatibility</strong> – All standard options supported.</li>
  <li>✅ <strong>Automatic installer</strong> – Adds itself to system <code>PATH</code>.</li>
  <li>✅ <strong>No admin required</strong> to run (only for installation).</li>
  <li>✅ <strong>Lightweight and fast</strong> – Built with Python + PyInstaller.</li>
</ul>

<h3>📥 Download & Installation</h3>
<ol>
  <li>Go to the <a href="../../releases">Releases page</a>.</li>
  <li>Download <code>Dig-setup.exe</code> for automatic installation, or <code>dig.exe</code> for portable use.</li>
  <li><strong>To install:</strong> Run <code>Dig-setup.exe</code> as Administrator and follow the prompts.</li>
  <li><strong>Portable use:</strong> Place <code>dig.exe</code> in any folder and open Command Prompt there.</li>
  <li>After installation, open <code>cmd</code> and try: <code>dig google.com</code></li>
</ol>

<h3>🛠️ Usage Examples</h3>
<pre>
dig google.com                 # Standard A record lookup
dig google.com MX              # Mail server lookup
dig -x 8.8.8.8                 # Reverse DNS lookup
dig example.com +short         # Short output
dig example.com +trace         # Trace delegation path
</pre>

<h3>🔧 Build from Source</h3>
<p>To build the executable yourself:</p>
<pre>
git clone https://github.com/AHX47/dig-for-windows.git
cd dig-for-windows
build.bat
</pre>
<p>Requirements: Python 3.9+ (PyInstaller will be installed automatically).</p>

<h3>👨‍💻 Author</h3>
<p>
  <strong>abdo_hak47</strong><br>
  📍 Laghouat, Algeria<br>
  🎓 Student at University Amar Telidji<br>
  🐙 <a href="https://github.com/AHX47">GitHub</a>
</p>

<h3>📜 License</h3>
<p>This project is licensed under the <a href="https://github.com/AHX47/Dig-for-windows/blob/main/License.txt">MIT License</a>.</p>
