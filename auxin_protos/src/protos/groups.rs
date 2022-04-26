#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AvatarUploadAttributes {
    #[prost(string, tag="1")]
    pub key: ::prost::alloc::string::String,
    #[prost(string, tag="2")]
    pub credential: ::prost::alloc::string::String,
    #[prost(string, tag="3")]
    pub acl: ::prost::alloc::string::String,
    #[prost(string, tag="4")]
    pub algorithm: ::prost::alloc::string::String,
    #[prost(string, tag="5")]
    pub date: ::prost::alloc::string::String,
    #[prost(string, tag="6")]
    pub policy: ::prost::alloc::string::String,
    #[prost(string, tag="7")]
    pub signature: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Member {
    #[prost(bytes="vec", tag="1")]
    pub user_id: ::prost::alloc::vec::Vec<u8>,
    #[prost(enumeration="member::Role", tag="2")]
    pub role: i32,
    #[prost(bytes="vec", tag="3")]
    pub profile_key: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes="vec", tag="4")]
    pub presentation: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint32, tag="5")]
    pub joined_at_revision: u32,
}
/// Nested message and enum types in `Member`.
pub mod member {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Role {
        Unknown = 0,
        Default = 1,
        Administrator = 2,
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PendingMember {
    #[prost(message, optional, tag="1")]
    pub member: ::core::option::Option<Member>,
    #[prost(bytes="vec", tag="2")]
    pub added_by_user_id: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag="3")]
    pub timestamp: u64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RequestingMember {
    #[prost(bytes="vec", tag="1")]
    pub user_id: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes="vec", tag="2")]
    pub profile_key: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes="vec", tag="3")]
    pub presentation: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag="4")]
    pub timestamp: u64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AccessControl {
    #[prost(enumeration="access_control::AccessRequired", tag="1")]
    pub attributes: i32,
    #[prost(enumeration="access_control::AccessRequired", tag="2")]
    pub members: i32,
    #[prost(enumeration="access_control::AccessRequired", tag="3")]
    pub add_from_invite_link: i32,
}
/// Nested message and enum types in `AccessControl`.
pub mod access_control {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum AccessRequired {
        Unknown = 0,
        Any = 1,
        Member = 2,
        Administrator = 3,
        Unsatisfiable = 4,
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Group {
    #[prost(bytes="vec", tag="1")]
    pub public_key: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes="vec", tag="2")]
    pub title: ::prost::alloc::vec::Vec<u8>,
    #[prost(string, tag="3")]
    pub avatar: ::prost::alloc::string::String,
    #[prost(bytes="vec", tag="4")]
    pub disappearing_messages_timer: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag="5")]
    pub access_control: ::core::option::Option<AccessControl>,
    #[prost(uint32, tag="6")]
    pub revision: u32,
    #[prost(message, repeated, tag="7")]
    pub members: ::prost::alloc::vec::Vec<Member>,
    #[prost(message, repeated, tag="8")]
    pub pending_members: ::prost::alloc::vec::Vec<PendingMember>,
    #[prost(message, repeated, tag="9")]
    pub requesting_members: ::prost::alloc::vec::Vec<RequestingMember>,
    #[prost(bytes="vec", tag="10")]
    pub invite_link_password: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes="vec", tag="11")]
    pub description: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GroupChange {
    #[prost(bytes="vec", tag="1")]
    pub actions: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes="vec", tag="2")]
    pub server_signature: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint32, tag="3")]
    pub change_epoch: u32,
}
/// Nested message and enum types in `GroupChange`.
pub mod group_change {
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Actions {
        #[prost(bytes="vec", tag="1")]
        pub source_uuid: ::prost::alloc::vec::Vec<u8>,
        #[prost(uint32, tag="2")]
        pub revision: u32,
        #[prost(message, repeated, tag="3")]
        pub add_members: ::prost::alloc::vec::Vec<actions::AddMemberAction>,
        #[prost(message, repeated, tag="4")]
        pub delete_members: ::prost::alloc::vec::Vec<actions::DeleteMemberAction>,
        #[prost(message, repeated, tag="5")]
        pub modify_member_roles: ::prost::alloc::vec::Vec<actions::ModifyMemberRoleAction>,
        #[prost(message, repeated, tag="6")]
        pub modify_member_profile_keys: ::prost::alloc::vec::Vec<actions::ModifyMemberProfileKeyAction>,
        #[prost(message, repeated, tag="7")]
        pub add_pending_members: ::prost::alloc::vec::Vec<actions::AddPendingMemberAction>,
        #[prost(message, repeated, tag="8")]
        pub delete_pending_members: ::prost::alloc::vec::Vec<actions::DeletePendingMemberAction>,
        #[prost(message, repeated, tag="9")]
        pub promote_pending_members: ::prost::alloc::vec::Vec<actions::PromotePendingMemberAction>,
        #[prost(message, optional, tag="10")]
        pub modify_title: ::core::option::Option<actions::ModifyTitleAction>,
        #[prost(message, optional, tag="11")]
        pub modify_avatar: ::core::option::Option<actions::ModifyAvatarAction>,
        #[prost(message, optional, tag="12")]
        pub modify_disappearing_messages_timer: ::core::option::Option<actions::ModifyDisappearingMessagesTimerAction>,
        #[prost(message, optional, tag="13")]
        pub modify_attributes_access: ::core::option::Option<actions::ModifyAttributesAccessControlAction>,
        #[prost(message, optional, tag="14")]
        pub modify_member_access: ::core::option::Option<actions::ModifyMembersAccessControlAction>,
        #[prost(message, optional, tag="15")]
        pub modify_add_from_invite_link_access: ::core::option::Option<actions::ModifyAddFromInviteLinkAccessControlAction>,
        #[prost(message, repeated, tag="16")]
        pub add_requesting_members: ::prost::alloc::vec::Vec<actions::AddRequestingMemberAction>,
        #[prost(message, repeated, tag="17")]
        pub delete_requesting_members: ::prost::alloc::vec::Vec<actions::DeleteRequestingMemberAction>,
        #[prost(message, repeated, tag="18")]
        pub promote_requesting_members: ::prost::alloc::vec::Vec<actions::PromoteRequestingMemberAction>,
        #[prost(message, optional, tag="19")]
        pub modify_invite_link_password: ::core::option::Option<actions::ModifyInviteLinkPasswordAction>,
        #[prost(message, optional, tag="20")]
        pub modify_description: ::core::option::Option<actions::ModifyDescriptionAction>,
    }
    /// Nested message and enum types in `Actions`.
    pub mod actions {
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct AddMemberAction {
            #[prost(message, optional, tag="1")]
            pub added: ::core::option::Option<super::super::Member>,
            #[prost(bool, tag="2")]
            pub join_from_invite_link: bool,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct DeleteMemberAction {
            #[prost(bytes="vec", tag="1")]
            pub deleted_user_id: ::prost::alloc::vec::Vec<u8>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct ModifyMemberRoleAction {
            #[prost(bytes="vec", tag="1")]
            pub user_id: ::prost::alloc::vec::Vec<u8>,
            #[prost(enumeration="super::super::member::Role", tag="2")]
            pub role: i32,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct ModifyMemberProfileKeyAction {
            #[prost(bytes="vec", tag="1")]
            pub presentation: ::prost::alloc::vec::Vec<u8>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct AddPendingMemberAction {
            #[prost(message, optional, tag="1")]
            pub added: ::core::option::Option<super::super::PendingMember>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct DeletePendingMemberAction {
            #[prost(bytes="vec", tag="1")]
            pub deleted_user_id: ::prost::alloc::vec::Vec<u8>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct PromotePendingMemberAction {
            #[prost(bytes="vec", tag="1")]
            pub presentation: ::prost::alloc::vec::Vec<u8>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct AddRequestingMemberAction {
            #[prost(message, optional, tag="1")]
            pub added: ::core::option::Option<super::super::RequestingMember>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct DeleteRequestingMemberAction {
            #[prost(bytes="vec", tag="1")]
            pub deleted_user_id: ::prost::alloc::vec::Vec<u8>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct PromoteRequestingMemberAction {
            #[prost(bytes="vec", tag="1")]
            pub user_id: ::prost::alloc::vec::Vec<u8>,
            #[prost(enumeration="super::super::member::Role", tag="2")]
            pub role: i32,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct ModifyTitleAction {
            #[prost(bytes="vec", tag="1")]
            pub title: ::prost::alloc::vec::Vec<u8>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct ModifyDescriptionAction {
            #[prost(bytes="vec", tag="1")]
            pub description: ::prost::alloc::vec::Vec<u8>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct ModifyAvatarAction {
            #[prost(string, tag="1")]
            pub avatar: ::prost::alloc::string::String,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct ModifyDisappearingMessagesTimerAction {
            #[prost(bytes="vec", tag="1")]
            pub timer: ::prost::alloc::vec::Vec<u8>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct ModifyAttributesAccessControlAction {
            #[prost(enumeration="super::super::access_control::AccessRequired", tag="1")]
            pub attributes_access: i32,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct ModifyMembersAccessControlAction {
            #[prost(enumeration="super::super::access_control::AccessRequired", tag="1")]
            pub members_access: i32,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct ModifyAddFromInviteLinkAccessControlAction {
            #[prost(enumeration="super::super::access_control::AccessRequired", tag="1")]
            pub add_from_invite_link_access: i32,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct ModifyInviteLinkPasswordAction {
            #[prost(bytes="vec", tag="1")]
            pub invite_link_password: ::prost::alloc::vec::Vec<u8>,
        }
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GroupChanges {
    #[prost(message, repeated, tag="1")]
    pub group_changes: ::prost::alloc::vec::Vec<group_changes::GroupChangeState>,
}
/// Nested message and enum types in `GroupChanges`.
pub mod group_changes {
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct GroupChangeState {
        #[prost(message, optional, tag="1")]
        pub group_change: ::core::option::Option<super::GroupChange>,
        #[prost(message, optional, tag="2")]
        pub group_state: ::core::option::Option<super::Group>,
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GroupAttributeBlob {
    #[prost(oneof="group_attribute_blob::Content", tags="1, 2, 3, 4")]
    pub content: ::core::option::Option<group_attribute_blob::Content>,
}
/// Nested message and enum types in `GroupAttributeBlob`.
pub mod group_attribute_blob {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Content {
        #[prost(string, tag="1")]
        Title(::prost::alloc::string::String),
        #[prost(bytes, tag="2")]
        Avatar(::prost::alloc::vec::Vec<u8>),
        #[prost(uint32, tag="3")]
        DisappearingMessagesDuration(u32),
        #[prost(string, tag="4")]
        Description(::prost::alloc::string::String),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GroupInviteLink {
    #[prost(oneof="group_invite_link::Contents", tags="1")]
    pub contents: ::core::option::Option<group_invite_link::Contents>,
}
/// Nested message and enum types in `GroupInviteLink`.
pub mod group_invite_link {
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct GroupInviteLinkContentsV1 {
        #[prost(bytes="vec", tag="1")]
        pub group_master_key: ::prost::alloc::vec::Vec<u8>,
        #[prost(bytes="vec", tag="2")]
        pub invite_link_password: ::prost::alloc::vec::Vec<u8>,
    }
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Contents {
        #[prost(message, tag="1")]
        V1Contents(GroupInviteLinkContentsV1),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GroupJoinInfo {
    #[prost(bytes="vec", tag="1")]
    pub public_key: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes="vec", tag="2")]
    pub title: ::prost::alloc::vec::Vec<u8>,
    #[prost(string, tag="3")]
    pub avatar: ::prost::alloc::string::String,
    #[prost(uint32, tag="4")]
    pub member_count: u32,
    #[prost(enumeration="access_control::AccessRequired", tag="5")]
    pub add_from_invite_link: i32,
    #[prost(uint32, tag="6")]
    pub revision: u32,
    #[prost(bool, tag="7")]
    pub pending_admin_approval: bool,
    #[prost(bytes="vec", tag="8")]
    pub description: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GroupExternalCredential {
    #[prost(string, tag="1")]
    pub token: ::prost::alloc::string::String,
}
/// Decrypted version of Member
/// Keep field numbers in step
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DecryptedMember {
    #[prost(bytes="vec", tag="1")]
    pub uuid: ::prost::alloc::vec::Vec<u8>,
    #[prost(enumeration="member::Role", tag="2")]
    pub role: i32,
    #[prost(bytes="vec", tag="3")]
    pub profile_key: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint32, tag="5")]
    pub joined_at_revision: u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DecryptedPendingMember {
    #[prost(bytes="vec", tag="1")]
    pub uuid: ::prost::alloc::vec::Vec<u8>,
    #[prost(enumeration="member::Role", tag="2")]
    pub role: i32,
    #[prost(bytes="vec", tag="3")]
    pub added_by_uuid: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag="4")]
    pub timestamp: u64,
    #[prost(bytes="vec", tag="5")]
    pub uuid_cipher_text: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DecryptedRequestingMember {
    #[prost(bytes="vec", tag="1")]
    pub uuid: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes="vec", tag="2")]
    pub profile_key: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag="4")]
    pub timestamp: u64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DecryptedPendingMemberRemoval {
    #[prost(bytes="vec", tag="1")]
    pub uuid: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes="vec", tag="2")]
    pub uuid_cipher_text: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DecryptedApproveMember {
    #[prost(bytes="vec", tag="1")]
    pub uuid: ::prost::alloc::vec::Vec<u8>,
    #[prost(enumeration="member::Role", tag="2")]
    pub role: i32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DecryptedModifyMemberRole {
    #[prost(bytes="vec", tag="1")]
    pub uuid: ::prost::alloc::vec::Vec<u8>,
    #[prost(enumeration="member::Role", tag="2")]
    pub role: i32,
}
/// Decrypted version of message Group
/// Keep field numbers in step
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DecryptedGroup {
    #[prost(string, tag="2")]
    pub title: ::prost::alloc::string::String,
    #[prost(string, tag="3")]
    pub avatar: ::prost::alloc::string::String,
    #[prost(message, optional, tag="4")]
    pub disappearing_messages_timer: ::core::option::Option<DecryptedTimer>,
    #[prost(message, optional, tag="5")]
    pub access_control: ::core::option::Option<AccessControl>,
    #[prost(uint32, tag="6")]
    pub revision: u32,
    #[prost(message, repeated, tag="7")]
    pub members: ::prost::alloc::vec::Vec<DecryptedMember>,
    #[prost(message, repeated, tag="8")]
    pub pending_members: ::prost::alloc::vec::Vec<DecryptedPendingMember>,
    #[prost(message, repeated, tag="9")]
    pub requesting_members: ::prost::alloc::vec::Vec<DecryptedRequestingMember>,
    #[prost(bytes="vec", tag="10")]
    pub invite_link_password: ::prost::alloc::vec::Vec<u8>,
    #[prost(string, tag="11")]
    pub description: ::prost::alloc::string::String,
}
/// Decrypted version of message GroupChange.Actions
/// Keep field numbers in step
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DecryptedGroupChange {
    #[prost(bytes="vec", tag="1")]
    pub editor: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint32, tag="2")]
    pub revision: u32,
    #[prost(message, repeated, tag="3")]
    pub new_members: ::prost::alloc::vec::Vec<DecryptedMember>,
    #[prost(bytes="vec", repeated, tag="4")]
    pub delete_members: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    #[prost(message, repeated, tag="5")]
    pub modify_member_roles: ::prost::alloc::vec::Vec<DecryptedModifyMemberRole>,
    #[prost(message, repeated, tag="6")]
    pub modified_profile_keys: ::prost::alloc::vec::Vec<DecryptedMember>,
    #[prost(message, repeated, tag="7")]
    pub new_pending_members: ::prost::alloc::vec::Vec<DecryptedPendingMember>,
    #[prost(message, repeated, tag="8")]
    pub delete_pending_members: ::prost::alloc::vec::Vec<DecryptedPendingMemberRemoval>,
    #[prost(message, repeated, tag="9")]
    pub promote_pending_members: ::prost::alloc::vec::Vec<DecryptedMember>,
    #[prost(message, optional, tag="10")]
    pub new_title: ::core::option::Option<DecryptedString>,
    #[prost(message, optional, tag="11")]
    pub new_avatar: ::core::option::Option<DecryptedString>,
    #[prost(message, optional, tag="12")]
    pub new_timer: ::core::option::Option<DecryptedTimer>,
    #[prost(enumeration="access_control::AccessRequired", tag="13")]
    pub new_attribute_access: i32,
    #[prost(enumeration="access_control::AccessRequired", tag="14")]
    pub new_member_access: i32,
    #[prost(enumeration="access_control::AccessRequired", tag="15")]
    pub new_invite_link_access: i32,
    #[prost(message, repeated, tag="16")]
    pub new_requesting_members: ::prost::alloc::vec::Vec<DecryptedRequestingMember>,
    #[prost(bytes="vec", repeated, tag="17")]
    pub delete_requesting_members: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    #[prost(message, repeated, tag="18")]
    pub promote_requesting_members: ::prost::alloc::vec::Vec<DecryptedApproveMember>,
    #[prost(bytes="vec", tag="19")]
    pub new_invite_link_password: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag="20")]
    pub new_description: ::core::option::Option<DecryptedString>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DecryptedString {
    #[prost(string, tag="1")]
    pub value: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DecryptedTimer {
    #[prost(uint32, tag="1")]
    pub duration: u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DecryptedGroupJoinInfo {
    #[prost(string, tag="2")]
    pub title: ::prost::alloc::string::String,
    #[prost(string, tag="3")]
    pub avatar: ::prost::alloc::string::String,
    #[prost(uint32, tag="4")]
    pub member_count: u32,
    #[prost(enumeration="access_control::AccessRequired", tag="5")]
    pub add_from_invite_link: i32,
    #[prost(uint32, tag="6")]
    pub revision: u32,
    #[prost(bool, tag="7")]
    pub pending_admin_approval: bool,
    #[prost(string, tag="8")]
    pub description: ::prost::alloc::string::String,
}
