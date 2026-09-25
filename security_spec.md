# Especificación de Seguridad Firestore (Zero-Trust ABAC)

## 1. Data Invariants
- **Identidad Canónica & Sacramental**: Ninguna solicitud sacramental (`certificateRequests`) o inscripción educativa (`courseEnrollments`) puede ser creada o consultada sin vinculación estricta al `request.auth.uid`.
- **Inmutabilidad de Identidad y Auditoría**: El campo `userId` no puede ser suplantado tras la creación (`incoming().userId == existing().userId`).
- **Control de Acceso Basado en Roles (RBAC Eclesiástico)**: Modificaciones de estado canónico (`status`) o consulta de correspondencia administrativa institucional solo están permitidas para administradores verificados (`isAdmin()`).
- **Defensa contra Envenenamiento de Recursos (Denial of Wallet)**: Todas las cadenas están delimitadas por longitud (`size() <= N`), identificadores estrictamente regex-validados, y payloads verificados con helpers dedicados.
- **Admin Bootstrapped**: Administrador inicial autorizado por correo verificado: `multicreativo@gmail.com`.

## 2. Dirty Dozen Payloads (Rechazados por Reglas)
1. Inyección de ID corrupto con caracteres especiales (`/certificateRequests/$$$malicious$$$`)
2. Creación anónima de certificado sin `request.auth`
3. Suplantación de identidad `userId` ajeno en solicitud de partida de bautismo
4. Intento de auto-promoción a administrador en `/admins/{uid}`
5. Modificación no autorizada de estado sacramental de 'pendiente' a 'entregado' por usuario común
6. Payload inflado en mensaje de contacto con longitud > 5000 caracteres
7. Actualización de campo inmutable `userId` en solicitud sacramental existente
8. Creación de solicitud con campos fantasma adicionales no declarados en el esquema
9. Lectura masiva no restringida (blanket read) en `/certificateRequests`
10. Consulta de buzón institucional `/contactMessages` por usuario no administrador
11. Lectura o escritura en colecciones protegidas del sistema sin pasar por el Master Gate
12. Envío de timestamp futuro o manipulado por cliente
