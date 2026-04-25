# Multi-Router Implementation Summary

## Overview

The system has been updated to support multiple MikroTik routers, where each router has its own session and PPPoE users are associated with their specific router.

## Key Changes

### 1. Database Schema Updates

**Added `mikrotik_router_id` to `pppoe_routers` table:**
- Foreign key linking PPPoE users to their MikroTik router
- Unique constraint: `(mikrotik_router_id, pppoe_username)` - ensures usernames are unique per router
- Cascade delete: When a router is deleted, its PPPoE users are also deleted

**Migration:**
- The system automatically adds the `mikrotik_router_id` column to existing databases
- Existing PPPoE users will have `NULL` for `mikrotik_router_id` initially
- You'll need to manually assign existing users to routers or they won't appear until assigned

### 2. Session Management

**Changed from storing credentials to storing router selection:**
- **Old:** Session stored router credentials directly (`host`, `port`, `username`, `password_enc`)
- **New:** Session stores `selected_router_id` and credentials are fetched from database

**Session structure:**
```python
session["user"] = {
    "username": username,  # For display purposes
    "identity": identity,   # Router identity info
}
session["selected_router_id"] = router_id  # ID of selected router
```

### 3. Router Credentials Management

**New function: `get_session_router_credentials()`**
- Retrieves router credentials from database based on `selected_router_id`
- Returns credentials in the same format as before for compatibility
- Includes router metadata (router_id, router_name)

**New database functions:**
- `db_get_mikrotik_router_by_id(router_id)` - Get router by ID
- `db_list_mikrotik_routers()` - List all routers
- `db_get_pppoe_router_by_username(username, router_id=None)` - Get user by username (optionally filtered by router)
- `db_list_pppoe_routers(router_id=None)` - List PPPoE users (optionally filtered by router)

### 4. Router Selection

**New endpoints:**
- `POST /api/select-router` - Select a router to work with
- `GET /api/mikrotik-routers` - Get list of all routers

**Updated login flow:**
1. User logs in with router credentials
2. System checks if router exists in database
3. If exists: Sets `selected_router_id` and redirects to dashboard
4. If not exists: Stores credentials temporarily and redirects to registration

### 5. PPPoE User Management

**All PPPoE operations now filter by router:**
- User listing: Only shows users for selected router
- User registration: Automatically associates with selected router
- User operations: Verifies user belongs to selected router before allowing operations

**New helper function:**
- `verify_user_belongs_to_router(user, router_id=None)` - Verifies user ownership

### 6. Updated Functions

**Functions that now filter by router_id:**
- `db_list_pppoe_routers(router_id=None)` - Lists users for specific router
- `db_get_pppoe_router_by_username(username, router_id=None)` - Gets user for specific router
- `check_and_disable_expired_accounts()` - Only checks users for selected router
- All user management pages and APIs

## Usage Guide

### Registering a New Router

1. Navigate to `/mikrotik` (MikroTik Registration page)
2. Fill in router details:
   - Router Name
   - Router Role (core, access, edge)
   - Management IP
   - API Port (8728 or 8729)
   - Use SSL
   - API Username
   - API Password
3. Click "Register Router"
4. System verifies connection and stores router
5. Router is automatically selected if you're logged in

### Selecting a Router

**Via API:**
```javascript
POST /api/select-router
{
    "router_id": 1
}
```

**Via Dashboard:**
- Dashboard now shows router selection dropdown
- Select a router from the list to switch contexts

### Registering PPPoE Users

1. **Select a router** (must be done first)
2. Navigate to User Management or use API
3. Register new PPPoE user
4. User is automatically associated with the selected router

### Managing Multiple Routers

**Workflow:**
1. Login (system will auto-select router if credentials match)
2. If needed, select different router via `/api/select-router`
3. All operations (view users, register users, etc.) work with selected router
4. Switch routers anytime by selecting a different router

## API Changes

### New Endpoints

**Select Router:**
```
POST /api/select-router
Body: { "router_id": 1 }
Response: { "message": "...", "router": {...} }
```

**List Routers:**
```
GET /api/mikrotik-routers
Response: [{ "id": 1, "name": "...", "role": "...", "is_selected": true }, ...]
```

### Updated Endpoints

**All PPPoE endpoints now:**
- Require a selected router
- Filter results by selected router
- Verify user ownership before operations

**Error responses:**
- `400 Bad Request` - No router selected
- `403 Forbidden` - User doesn't belong to selected router
- `404 Not Found` - Router or user not found

## Database Migration Notes

### For Existing Installations

1. **Run the application** - It will automatically add the `mikrotik_router_id` column
2. **Assign existing users to routers:**
   ```sql
   -- Example: Assign all users to router ID 1
   UPDATE pppoe_routers 
   SET mikrotik_router_id = 1 
   WHERE mikrotik_router_id IS NULL;
   ```
3. **Or delete orphaned users:**
   ```sql
   DELETE FROM pppoe_routers WHERE mikrotik_router_id IS NULL;
   ```

### Schema Changes

**Before:**
```sql
CREATE TABLE pppoe_routers (
    id INT PRIMARY KEY,
    pppoe_username VARCHAR(100) UNIQUE,
    ...
);
```

**After:**
```sql
CREATE TABLE pppoe_routers (
    id INT PRIMARY KEY,
    mikrotik_router_id INT NOT NULL,
    pppoe_username VARCHAR(100),
    ...
    UNIQUE KEY unique_username_per_router (mikrotik_router_id, pppoe_username),
    FOREIGN KEY (mikrotik_router_id) REFERENCES routers(id) ON DELETE CASCADE
);
```

## Security Improvements

1. **Router Isolation:** Users can only see/manage users for their selected router
2. **Ownership Verification:** All operations verify user belongs to selected router
3. **Session-Based Selection:** Router selection is stored in session, not in URL parameters

## Breaking Changes

1. **Session Structure:** Old sessions will need to re-login
2. **PPPoE Username Uniqueness:** Now per-router instead of globally unique
3. **API Responses:** Some endpoints now return errors if no router is selected
4. **User Listing:** Only shows users for selected router

## Testing Checklist

- [ ] Register multiple routers
- [ ] Select different routers and verify user lists change
- [ ] Register PPPoE users for different routers
- [ ] Verify users are isolated per router
- [ ] Test router switching
- [ ] Verify expired account checking works per router
- [ ] Test API endpoints with router selection
- [ ] Verify user operations (enable/disable, speed limits) work correctly

## Future Enhancements

Potential improvements:
1. Router groups/permissions
2. Bulk operations across routers
3. Router health monitoring
4. Router statistics dashboard
5. Multi-router user search













