# نظام مراسلة فورية على Google Cloud

نظام مراسلة فورية كامل: بروتوكول مبني على MTProto فوق TCP و UDP و WebSocket،
تسع خدمات مكتوبة بـ Go، تخزين مدعوم بـ Kafka، مع Terraform و Cloud Build
لتشغيله على GKE.

English: [README.md](README.md).

---

## محتويات المشروع

```
pkg/                    المكتبات المشتركة
  mtproto/              البروتوكول: AES-IGE، اشتقاق المفاتيح، المغلّف، مصافحة DH
    codec/              تأطير النقل + طبقة التمويه obfuscation2
    transport/          TCP، UDP (تجزئة + تحقق من المسار)، WebSocket
  mtclient/             عميل كامل — يقود اختبارات النهاية للنهاية
  kafkax/ cassandrax/   عملاء طبقة البيانات
  redisx/ pgstore/      موثّقة بالتفصيل داخل الكود
  authn/ ratelimit/     بيانات الاعتماد وسطل الرموز الموزّع
  push/ gcsx/           إشعارات FCM ووسائط عبر روابط موقّعة
services/
  auth-service/         التحقق بالهاتف، إصدار JWT، إدارة الأجهزة
  chat-service/         مسار كتابة الرسائل وإدارة المحادثات
  realtime-gateway/     ينهي اتصالات MTProto عبر ثلاث قنوات نقل
  presence-service/     من متصل الآن، وعلى أي جهاز
  media-service/        روابط رفع وتنزيل موقّعة
  notification-service/ إرسال إشعارات FCM
  consumers/            persister، pusher، indexer
db/                     مخطط Cassandra وترحيلات Postgres
deploy/
  terraform/            البنية التحتية الكاملة، ثلاث بيئات
  k8s/                  kustomize base + طبقات dev/staging/prod
  cloudbuild/           خط أنابيب لكل خدمة، وتحقق للـ pull requests
  clouddeploy/          staging ← canary ← production
build/                  ملفات Docker
tools/loadgen/          عملاء اصطناعيون على البروتوكول الحقيقي
docs/                   المعمارية، الأمان، دليل التشغيل، التكلفة
```

## البدء السريع

```bash
make dev-up && make dev-migrate
```

يشغّل Kafka و Cassandra و Postgres و Redis و Elasticsearch داخل Docker ويطبّق
المخططين. ثم في نوافذ منفصلة:

```bash
make run-auth
```

```bash
make run-chat
```

```bash
make run-gateway
```

الأمر `make help` يعرض كل الأوامر المتاحة.

## التحقق

```bash
make check
```

يشغّل `go vet` وفحص التنسيق ومجموعة الاختبارات كاملة مع كاشف السباقات
(race detector). للبنية التحتية والملفات:

```bash
make k8s-validate
```

```bash
make tf-validate
```

---

## رحلة الرسالة

```
  الهاتف ──MTProto/TCP──▶ realtime-gateway ──HTTP──▶ chat-service
                                                          │
                                    ┌────────────────────┼────────────────────┐
                                    ▼                    ▼                    ▼
                              Redis INCR          Kafka messages.raw    Redis pub/sub
                              (رقم التسلسل)        (acks=all — حدّ         (توزيع على
                                                     الاستدامة)          الأجهزة المتصلة)
                                                          │
                                                          ▼
                                                     persister
                                                     │        │
                                              Cassandra   messages.persisted
                                                               │        │
                                                           pusher    indexer
                                                           (FCM)   (Elasticsearch)
```

مسار الإرسال ست خطوات بهذا الترتيب:

1. التحقق من الصلاحية من ذاكرة العضوية في Redis، والرجوع إلى Postgres عند
   الفشل.
2. منع التكرار عبر `random_id` الذي يرسله العميل.
3. تخصيص رقم تسلسل متصل لكل محادثة (`INCR` في Redis).
4. النشر إلى Kafka بـ `acks=all`. **هنا يقع حدّ الاستدامة.**
5. التوزيع عبر Redis pub/sub على المتصلين حالياً.
6. إرجاع رقم التسلسل للمُرسِل.

Cassandra ليست في هذا المسار عن قصد. `acks=all` في Kafka يعني أن الرسالة نجت
من فشل أي وسيط، فانتظار Cassandra أيضاً كان سيضاعف زمن الإرسال دون أي ضمان
إضافي. الـ persister يكتبها بعد أجزاء من الثانية.

## القرارات التي تستحق المعرفة

**موزّعا حِمل، لا واحد.** الـ Global External HTTPS LB وسيط على الطبقة السابعة:
لا يستطيع حمل MTProto الخام فوق TCP، ولا يملك مساراً لـ UDP أصلاً. أما
Network LB في وضع التمرير (passthrough) فيحمل الاثنين، ويحافظ على عنوان
العميل الحقيقي كي يرى تحديد المعدّل عناوين فعلية.

**Redis يحمل عدّادات التسلسل، لذلك `maxmemory-policy` هي `noeviction`.**
الحدس يقول `allkeys-lru`، وهو خطأ هنا: حذف عدّاد محادثة بصمت سيعيد تسلسلها من
نقطة سابقة في منتصف المحادثة ويكتب فوق التاريخ. فشل الكتابة بصوت عالٍ عند
امتلاء الذاكرة أفضل بكثير.

**أقسام Cassandra محدودة بـ 10 آلاف رسالة.** تاريخ المحادثة غير محدود،
والقسم غير المحدود هو الطريقة الكلاسيكية لقتل عنقود Cassandra.

**البوابة لا تستطيع الوصول إلى Postgres ولا Cassandra.** هي الطبقة الأكثر
انكشافاً على الإنترنت ولا تحمل أي منطق أعمال، فاختراقها لا يجب أن يكون طريقاً
إلى البيانات — مفروض عبر NetworkPolicy و IAM معاً.

**الإشعارات تُرسل من `messages.persisted` لا من `messages.raw`.** إيقاظ هاتف
لأجل رسالة قد يضيعها فشل لاحق هو أسوأ أنواع الأخطاء: مرئي، وغير قابل للتفسير،
وغير قابل للاسترجاع.

**لا توجد مفاتيح حسابات خدمة في أي مكان.** Workload Identity يربط كل حساب
خدمة في Kubernetes بحساب Google، وخادم البيانات الوصفية يصدر رموزاً قصيرة
العمر.

## البروتوكول: ما هو أصيل وما هو مختلف

التشفير وطبقة النقل مطابقان لـ MTProto 2.0:

- AES-256-IGE بنفس تسلسل الكتل المستخدم في تليجرام، مثبّت باختبار إجابة معروفة.
- بناء `msg_key` واشتقاق مفتاح AES ومتجه التهيئة بالتداخل، مع فصل الاتجاهين
  عبر `x=0` و `x=8`.
- المغلّف: `auth_key_id ‖ msg_key ‖ AES-IGE(salt ‖ session_id ‖ msg_id ‖
  seq_no ‖ length ‖ body ‖ padding)`.
- دلالات `msg_id`، ورفض إعادة التشغيل، والنافذة الزمنية.
- مصافحة مفتاح المصادقة: إثبات العمل عبر `req_pq`، و`new_nonce` مغلّف بـ RSA،
  وتبادل Diffie-Hellman بطول 2048 بت.
- التأطيرات abridged و intermediate و padded-intermediate، بالإضافة إلى
  obfuscation2.

**حمولة الـ RPC ليست TL.** الاستدعاء هو معرّف بنّاء بأربعة بايتات يليه جسم
JSON. مخطط TL في تليجرام ملف ضخم مُولّد ومرتبط بإصدار، وحمل نسخة يدوية منه
كان سيكون كلفة صيانة دائمة لمنصة نكتب عملاءها بأنفسنا.

**بصراحة: عميل تليجرام الرسمي لا يستطيع التحدث مع هذا الخادم.** هذا ليس
تطبيقاً متوافقاً مع تليجرام، بل بروتوكول مراسلة مبني على تصميم MTProto
التشفيري وطبقة نقله. كل ما فوق حدود الحمولة لم يتغير، فاستبدال الترميز بـ TL
حقيقي يعني تعديل ملف واحد: `pkg/mtproto/tl.go`.

مجموعة Diffie-Hellman هي RFC 3526 MODP group 14 بدلاً من عدد تليجرام الأولي
الخاص: مجموعة منشورة ومراجَعة على نطاق واسع بنفس الخصائص، ويستطيع العميل
التحقق منها مقابل الـ RFC بدل الوثوق بالخادم.

## النشر

```bash
cd deploy/terraform && terraform init -backend-config=envs/prod/backend.hcl
```

```bash
terraform apply -var-file=envs/prod/terraform.tfvars
```

التطبيق يتم على مرحلتين، و`terraform output next_steps` يطبع بالضبط ما يجب
فعله بينهما: خلفية موزّع الحمل HTTPS هي network endpoint group ينشئها متحكم
GKE Gateway، فلا وجود لها قبل قيام العنقود ونشر الأحمال.

ثم زرع الأسرار — Terraform لا يحمل أي قيمة سرية إطلاقاً، لأن ملف الحالة ملف
يُنسخ ويُقارَن:

```bash
./scripts/bootstrap-secrets.sh messaging-prod prod
```

```bash
kubectl apply -k deploy/k8s/overlays/prod
```

## التوثيق

| | |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | التصميم مكوّناً بمكوّن، والمقايضات وراءه |
| [docs/SECURITY.md](docs/SECURITY.md) | نموذج التهديد، وما هو محمي وما ليس كذلك بعد |
| [docs/RUNBOOK.md](docs/RUNBOOK.md) | إجراءات الحوادث والعمليات الدورية |
| [docs/COST.md](docs/COST.md) | التكلفة، وأي المقابض تحرّكها |
| [docs/API.md](docs/API.md) | واجهات REST و MTProto |

## ما لم يُبنَ

مذكور هنا صراحةً بدل أن يُكتشف لاحقاً:

- **عميل iOS.** توجد ثلاث تطبيقات مستقلة لبروتوكول MTProto — بلغة Go
  (`pkg/mtclient`) و TypeScript (`web/lib/mtproto`) و Kotlin
  (`android/mtproto`)، وكلها مثبّتة على نفس متجهات الاختبار — لكن لا يوجد
  تطبيق بلغة Swift.
- **منظومة إشراف إنتاجية.** موضوع `user.events` يحمل الإشارات التي تستهلكها
  مثل هذه المنظومة، وسجل التدقيق يوثّق ما يفعله المشرف، لكن لا يوجد تصنيف
  للمحتوى ولا تقييم للسمعة.
- **حفظ نسخة من مفاتيح المحادثات السرية على الخادم — عن قصد.** الخادم مجرّد
  ناقل أعمى لها، وهذا هو الهدف؛ ويعني أيضاً أن من يفقد كل أجهزته يفقد ذلك
  السجل.
- **نشر إنتاجي مُتحقَّق منه.** كل بوابات التحقق أدناه تمرّ بنجاح، لكن لم
  يتوفّر مشروع GCP، فالمخططات مُتحقَّق منها مقابل مخطط Kubernetes لا مُطبَّقة
  فعلياً، و Terraform نظيف عند `validate` لا عند `plan` مقابل مشروع حقيقي.

يُشغَّل التحقق عبر `make check` وبوابات
[deploy/cloudbuild/pr-validate.yaml](deploy/cloudbuild/pr-validate.yaml):
اختبارات `go test -race` لكل الحزم، و `tsc` واختبارات التعمية في الويب،
واختبارات وحدة Kotlin، والمتجهات المشتركة التي تُثبّت تطبيقات البروتوكول
الثلاثة على نفس البايتات، و `kubeconform` على الطبقات الثلاث، و
`terraform validate`.

بعض الاختبارات تحتاج Redis حقيقياً لتكون ذات معنى — فسطل الرموز في محدّد
المعدّل نص Lua، والمحاكاة لا تثبت إلا أن المحاكاة تعمل. هذه الاختبارات
تُتخطّى بوضوح عند غياب الخادم بدل أن تمرّ بصمت:

```bash
docker run -d --rm -p 63799:6379 redis:7-alpine
```
