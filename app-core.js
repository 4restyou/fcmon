/* ═══════════════════════════════════════════════════════════════════
   FCMON 공용 코어 (app-core.js)
   모든 페이지에서 Firebase SDK 로드 직후, 페이지 스크립트보다 먼저 로드한다.
   - Firebase 초기화 (설정을 한 곳에서 관리)
   - 전역 db 핸들
   - Cloud Functions 베이스 URL
   - 공용 유틸: escapeHtml, safePhotoUrl
   ═══════════════════════════════════════════════════════════════════ */

var firebaseConfig = {
  apiKey: "AIzaSyB23qdSj0wknPB-WfNdoSvhdYRcQkrSYyU",
  authDomain: "fcmon-96ec1.firebaseapp.com",
  projectId: "fcmon-96ec1",
  storageBucket: "fcmon-96ec1.firebasestorage.app",
  messagingSenderId: "912620232254",
  appId: "1:912620232254:web:b86a27fa9f733f2c137b6f"
};
firebase.initializeApp(firebaseConfig);
var db = firebase.firestore();
var AUTH_FUNCTIONS_BASE_URL = "https://us-central1-fcmon-96ec1.cloudfunctions.net";

/* 🛡 XSS 방어: 사용자 입력을 HTML에 넣기 전 이스케이프 */
function escapeHtml(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/* 안전한 사진 URL만 통과 (http(s) 또는 허용된 data:image), 그 외 빈 문자열 */
function safePhotoUrl(url) {
  if (!url) return '';
  const s = String(url).trim();
  if (/^data:image\/(png|jpe?g|gif|webp|svg\+xml);/i.test(s)) return s;
  if (/^https?:\/\//i.test(s)) return s;
  return '';
}
