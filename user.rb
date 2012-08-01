class User < CouchRest::Model::Base

  collection_of :authentications

  # Include default devise modules. Others available are:
  # :registerable, :token_authenticatable, :encryptable, :confirmable and :omniauthable
  devise :database_authenticatable, :lockable, :timeoutable,
         :registerable, :recoverable, :rememberable, :trackable, :validatable, :invitable, :timeoutable

  use_database 'accounts'

  # Setup accessible (or protected) attributes for your model
  # attr_accessible :email, :password, :password_confirmation, :remember_me, :username
  
  attr_accessor :current_profile
  
  property :email, String
  property :username, String
  property :time_zone, String, :default => 'New Delhi'
  property :roles, [String], :default => ["author"]
  property :profiles, [String]
  property :invitation_token, String
  
  property :invitation_accepted_at, DateTime
  
  property :terms_of_service_and_privacy_policy, TrueClass, :default => false
#  property :roles_mask, Integer, :default => 2
#  property :password, String
#  property :password_confirmation, String
#  property :remember_me,             TrueClass, :default => false

  timestamps!
  
  property :profiles do
    property :id, String
    property :name, String
    property :relation, String
    property :relation_side, String  # Father or Mother
  end  

  validates_presence_of :username
  validates_uniqueness_of :username
  validates_acceptance_of :terms_of_service_and_privacy_policy, :allow_nil => false, :accept => true

  # design do
    # view :by_name
    # view :by_email
    # view :by_unlock_token
    # view :by_invitation_token
  # end
  
  view_by :name
  view_by :email
  view_by :username
  view_by :unlock_token
  view_by :invitation_token
  
  after_save :check_references
  
  # TODO Validate Roles one of [admin author viewer modifier]
  # TODO validate relation_side and relation 
   
  # ROLES = %w[admin author viewer modifier]
# 
#   scope :with_role, lambda { |role| {:conditions => "roles_mask & #{2**ROLES.index(role.to_s)} > 0 "} }
# 
  # def roles=(roles)
    # self.roles_mask = (roles & ROLES).map { |r| 2**ROLES.index(r) }.sum
  # end
# 
  # def roles
    # ROLES.reject { |r| ((roles_mask || 0) & 2**ROLES.index(r)).zero? }
  # end

  def role?(role)
    roles.include? role.to_s
  end
  
  def current_profile
    @current_profile || self.id
  end
  
  def current_profile=(profile)
    @current_profile = profile
  end

  # def role_symbols
    # roles.map(&:to_sym)
  # end

  def apply_omniauth(omniauth)
    self.email = omniauth['user_info']['email'] if email.blank?
    self.username = omniauth['user_info']['nickname'] if username.blank?
    @applied_auth = true
    
    if valid?
      # authentications.build(:provider => omniauth['provider'], :uid => omniauth['uid'])
      authentication = Authentication.create(:provider => omniauth['provider'], :uid => omniauth['uid'])
      authentications << authentication
      authentication.user = self
      logger.debug "authentication.user #{authentication.user.inspect}"
    end
    
  end

  def password_required?
    # (authentications.empty? || !password.blank?) && super
    (!@applied_auth || !password.blank?) && super
  end
  
  def destroy_authentication(authentication)
    logger.debug "self.authentication_ids : #{self.authentication_ids}"
    self.authentication_ids.delete(authentication.id)
    save
    authentication.destroy    
  end
  
# TODO profiles linked and optimized 
  
  def profile_names
    return @profile_names if !@profile_names.nil?
    @profile_names = Hash.new
    @profile_names[self.username] = self.id
    profiles.each do |profile|
      @profile_names[profile.name] = profile.id
    end
    @profile_names 
  end
  
  
private

  def check_references
    logger.debug "Inside check_references.."
    authentications.each do |authentication|
      if authentication.user_id.nil?
        authentication.user_id = self.id
        authentication.save
      end
    end
  end  

end
