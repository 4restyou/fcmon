# FCMON

풋살/축구 모임 관리 웹앱. 순수 HTML/CSS/JS 정적 사이트 + Firebase 백엔드.

- **호스팅**: Netlify (https://fcmon.netlify.app)
- **백엔드**: Firebase 프로젝트 `fcmon-96ec1` (Firestore, Storage, Cloud Functions)

## 구조

| 파일 | 역할 |
|---|---|
| `index.html` | 메인 (경기 목록) |
| `register.html` | 경기 참가 신청 |
| `attendance.html` | 출석 체크 |
| `members.html` | 멤버 목록 |
| `ranking.html` | 랭킹 |
| `profile.html` | 프로필 |
| `admin.html` | 관리자 |
| `common.css` | 공통 스타일 |
| `firestore.rules` | Firestore 보안 규칙 |
| `functions/` | Cloud Functions (비밀번호 검증 등) |

## 배포

- **사이트(HTML/CSS)**: Netlify 대시보드에 이 폴더를 드래그하거나, Netlify를 이 저장소에 연결하면 push 시 자동 배포
- **Firestore 규칙 / Functions**: `firebase deploy --only firestore:rules,functions` (Firebase CLI 로그인 필요)
